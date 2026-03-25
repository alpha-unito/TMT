#include "logger/SyscallLogger.hpp"
#include "processors/EventProcessor.hpp"
#include "processors/SwitchProcessor.hpp"

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <args.hxx>
#include <filesystem>

static void print_banner() {
    std::cout << R"(
████████╗███╗   ███╗████████╗
╚══██╔══╝████╗ ████║╚══██╔══╝
   ██║   ██╔████╔██║   ██║   
   ██║   ██║╚██╔╝██║   ██║   
   ██║   ██║ ╚═╝ ██║   ██║   
   ╚═╝   ╚═╝     ╚═╝   ╚═╝   
 T h r e a d   M o n i t o r i n g   T o o l
)" << std::endl;
}

static void usage(const char *prog) {
    std::cerr << "Usage:\n"
              << "  sudo " << prog << " --cmd \"<command to trace>\" [--print-raw]\n\n"
              << "Examples:\n"
              << "  sudo " << prog << " --cmd \"sleep 1\"\n"
              << "  sudo " << prog << " --cmd \"python3 thread_test.py\" --print-raw\n";
}

int main(int argc, char **argv) {
    print_banner();

    std::string cmd;
    bool print_raw = false;

    args::ArgumentParser parser(
        "TMT: Thread Monitoring Tool",
        "Trace threads and scheduling behavior of a target program using eBPF.");

    args::HelpFlag help(parser, "help", "Show this help message and exit", {'h', "help"});

    args::ValueFlag<std::string> cmd_flag(parser, "command",
                                          "Command to execute and trace (required)", {"cmd"});

    args::Flag print_raw_flag(parser, "print-raw", "Print raw kernel events as they are received",
                              {"print-raw"});

    try {
        parser.ParseCLI(argc, argv);
    } catch (const args::Help &) {
        std::cout << parser << std::endl;
        return 0;
    } catch (const args::ParseError &e) {
        std::cerr << e.what() << std::endl << std::endl;
        std::cerr << parser << std::endl;
        return 1;
    }

    if (!cmd_flag) {
        usage(argv[0]);
        std::cerr << std::endl << "Error: --cmd is required." << std::endl;
        return 1;
    }

    cmd       = args::get(cmd_flag);
    print_raw = print_raw_flag;

    SyscallLogger logger(100);
    logger.runCommand(cmd, print_raw);

    const auto &evs = logger.getEvents();
    if (evs.empty()) {
        std::cerr << "No events collected.\n";
        return 0;
    }

    std::filesystem::create_directories("out");

    EventProcessor ep(logger.getEvents(), logger.getRootPid());
    ep.buildTree(false);
    ep.computeIntervals(false);

    ep.storeToCsv("out/alive_series.csv");

    SwitchProcessor sp(evs);
    sp.buildSlices(false);
    sp.storeCsv("out/oncpu_slices.csv");
    sp.plotTopRuntimePerCPU(10, "ms");

    std::cout << "Done. Events: " << evs.size() << " | alive series written to out/alive_series.csv"
              << std::endl;

    std::cout << "Setting permission to 0777 to output directory" << std::endl;
    std::filesystem::permissions("out", std::filesystem::perms::all);
    for (auto &de : std::filesystem::recursive_directory_iterator("out")) {
        std::filesystem::permissions(de, std::filesystem::perms::all);
    }
    return 0;
}
