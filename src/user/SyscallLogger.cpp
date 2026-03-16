#include "logger/SyscallLogger.hpp"
#include "handlers/Clone.hpp"
#include "handlers/Clone3.hpp"
#include "handlers/Execve.hpp"
#include "handlers/Exit.hpp"
#include "handlers/ExitGroup.hpp"
#include "handlers/Fork.hpp"
#include "handlers/Switch.hpp"

#include <algorithm>
#include <csignal>
#include <fstream>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

SyscallLogger::SyscallLogger(const int timeout_ms) : _timeout_ms(timeout_ms), _root_pid(0) {
    _handlers.emplace_back(std::make_unique<ExecveHandler>(_timeout_ms));
    _handlers.emplace_back(std::make_unique<ForkHandler>(_timeout_ms));
    _handlers.emplace_back(std::make_unique<ExitHandler>(_timeout_ms));
    _handlers.emplace_back(std::make_unique<ExitGroupHandler>(_timeout_ms));
    _handlers.emplace_back(std::make_unique<SwitchHandler>(_timeout_ms));
    _handlers.emplace_back(std::make_unique<CloneHandler>(_timeout_ms));
    _handlers.emplace_back(std::make_unique<Clone3Handler>(_timeout_ms));
}

bool SyscallLogger::installAll() const {
    for (auto &h : _handlers) {
        if (!h->install()) {
            std::cerr << "Install failed for handler: " << h->getName() << std::endl;
            return false;
        }
    }
    return true;
}

void SyscallLogger::stop() {
    for (const auto &h : _handlers) {
        h->freezeProducer();
    }

    std::vector<uint64_t> totals;
    totals.reserve(_handlers.size());
    for (const auto &h : _handlers) {
        totals.push_back(h->snapshotTotal());
    }

    for (size_t i = 0; i < _handlers.size(); ++i) {
        _handlers[i]->drainUntil(totals[i]);
    }

    for (const auto &h : _handlers) {
        h->detach();
        h->stop();
    }

    _events.clear();
    for (const auto &h : _handlers) {
        auto v = h->collect();
        _events.insert(_events.end(), v.begin(), v.end());
    }
    std::sort(_events.begin(), _events.end(),
              [](const Event &a, const Event &b) { return a.timestamp < b.timestamp; });

    if (!_events.empty()) {
        const uint64_t t0 = _events.front().timestamp;
        for (auto &e : _events) {
            e.timestamp -= t0;
        }
    }
}

static std::vector<std::string> split_args(const std::string &cmd) {
    std::istringstream iss(cmd);
    std::vector<std::string> out;
    std::string tok;
    while (iss >> tok) {
        out.push_back(tok);
    }
    return out;
}

void SyscallLogger::runCommand(const std::string &cmd, const bool print_raw) {
    const pid_t cmd_pid = fork();
    if (cmd_pid < 0) {
        std::cerr << "fork() failed: " << strerror(errno) << "\n";
        return;
    }

    if (cmd_pid == 0) {
        // Stop early to let the parent install BPF handlers before exec/spawn.
        raise(SIGSTOP);
        const auto args = split_args(cmd);
        if (args.empty()) {
            std::cerr << "Empty command\n";
            _exit(127);
        }

        std::vector<char *> argv;
        argv.reserve(args.size() + 1);
        for (auto &s : args) {
            argv.push_back(const_cast<char *>(s.c_str()));
        }
        argv.push_back(nullptr);

        if (execvp(argv[0], argv.data()) < 0) {
            std::cerr << "execvp failed: " << strerror(errno) << "\n";
            _exit(127);
        }
    }

    // wait for child to stop so we can attach before it execs/spawns
    int st = 0;
    if (waitpid(cmd_pid, &st, WUNTRACED) < 0) {
        std::cerr << "waitpid (WUNTRACED) failed: " << strerror(errno) << "\n";
        return;
    }
    if (!WIFSTOPPED(st)) {
        std::cerr << "child did not stop as expected; continuing\n";
    }

    // pass cmd_pid to the Event Processor
    _root_pid = static_cast<uint32_t>(cmd_pid);

    // pass the cmd_pid to the SwitchHandler
    for (auto &h : _handlers) {
        if (auto *sh = dynamic_cast<SwitchHandler *>(h.get())) {
            sh->setRootPid(0, static_cast<uint32_t>(cmd_pid));
        }
    }

    if (!installAll()) {
        std::cerr << "No handler installed successfully; aborting.\n";
        kill(cmd_pid, SIGCONT);
        return;
    }

    // resume the child once handlers are installed
    kill(cmd_pid, SIGCONT);

    // wait the cmd end
    if (waitpid(cmd_pid, nullptr, 0) < 0) {
        std::cerr << "waitpid failed: " << strerror(errno) << "\n";
    }

    stop();

    if (print_raw) {
        for (auto &e : _events) {
            std::cout << e.timestamp << " " << e.event << " pid=" << e.pid
                      << " child=" << e.child_pid << " comm=" << e.command << "\n";
        }
    }
}

uint32_t SyscallLogger::getRootPid() const { return _root_pid; }

const std::vector<Event> &SyscallLogger::getEvents() const { return _events; }
