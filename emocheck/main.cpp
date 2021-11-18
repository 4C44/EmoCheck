/*
 * LICENSE
 * Please refer to the LICENSE.txt at https://github.com/JPCERTCC/EmoCheck/
 */

// emocheck module
#include "emocheck.hpp"
#include "utils/file.hpp"
#include "utils/utils.hpp"

// defines
#define PARAM_SWITCH1 '/'
#define PARAM_SWITCH2 '-'
#define PARAM_QUIET "quiet"
#define PARAM_DEBUG "debug"
#define PARAM_OUTPUT "output"
#define PARAM_HELP "help"
#define PARAM_JSON "json"

namespace emocheck {

bool is_param(const char *str) {
    if (!str) return false;

    const size_t len = strlen(str);
    if (len < 2) return false;

    if (str[0] == PARAM_SWITCH1 || str[0] == PARAM_SWITCH2) {
        return true;
    }
    return false;
}

void PrintBanner() {
    char banner[] =
        "  ______                  _____ _               _   \n"
        "|  ____|                / ____| |             | |   \n"
        "| |__   _ __ ___   ___ | |    | |__   ___  ___| | __\n"
        "|  __| | '_ ` _ ` / _ `| |    | '_ ` / _ `/ __| |/ /\n"
        "| |____| | | | | | (_) | |____| | | |  __/ (__|   < \n"
        "|______|_| |_| |_|`___/ `_____|_| |_|`___|`___|_|`_`\n";

    std::cout << LINE_DELIMITER
              << banner
              << LINE_DELIMITER << "\n"
              << "Emotet detection tool by JPCERT/CC.\n\n"
              << "Version      : " << EMOCHECK_VERSION << "\n"
              << "Release Date : " << EMOCHECK_RELEASE_DATE << "\n"
              << "URL          : " << EMOCHECK_URL << "\n"
              << LINE_DELIMITER << std::endl;

    // unsigned short int usrDefLangId = GetUserDefaultLangID();
}

void PrintHelp() {
    if (GetUserDefaultLangID() == LANG_ID_JP && !IsWindows7()) {
        SetConsoleOutputCP(CP_UTF8);
        // Japanese help
        std::cout << "[オプション説明]\n"
                  << "コマンドラインの出力抑止:\n\t /quiet  または -quiet\n"
                  << "JSON形式でのレポート出力:\n\t /json  または -json\n"
                  << "レポート出力先ディレクトリ指定 (デフォルト カレントディレクトリ):\n\t /output [出力先ディレクトリ] または -output [出力先ディレクトリ]\n"
                  << std::endl;
    } else if (GetUserDefaultLangID() == LANG_ID_FR && !IsWindows7()) {
        SetConsoleOutputCP(CP_UTF8);
        // French Help
        std::cout << "[Options]\n"
                  << "Exécution en mode silencieux:\n\t/quiet ou -quiet\n"
                  << "Exporter la sortie au format JSON:\n\t/json ou -json\n"
                  << "Répertoire de destination (par defaut: répertoire courant ):\n\t/output [destination] ou -output [destination]\n"
                  << "Mode verbeux:\n\t/debug ou -debug" << std::endl;
    } else {
        // English Help
        std::cout << "[Options]\n"
                  << "Suppress command line output:\n\t/quiet or -quiet\n"
                  << "Export report in JSON sytle:\n\t/json or -json\n"
                  << "Set output directory (default: current directory ):\n\t/output [output directory] or -output [output directory]\n"
                  << "Debug mode:\n\t/debug or -debug" << std::endl;
    }
}

void PrintReport(std::vector<EmotetProcess> emotet_processes) {
    if (GetUserDefaultLangID() == LANG_ID_JP && !IsWindows7()) {
        SetConsoleOutputCP(CP_UTF8);
        // Japanese Report
        if (emotet_processes.size() > 0) {
            std::cout.imbue(std::locale(""));
            for (unsigned int i = 0; i < emotet_processes.size(); ++i) {
                std::cout << "[!!] Emotet 検知"
                          << "\n"
                          << "     プロセス名    : " << emotet_processes[i].process_name << "\n"
                          << "     プロセスID    : " << emotet_processes[i].pid << "\n"
                          << "     イメージパス  : " << emotet_processes[i].image_path << std::endl;
            }
            std::cout << LINE_DELIMITER << std::endl;
            std::cout << "Emotetのプロセスが見つかりました。\n"
                      << "不審なイメージパスの実行ファイルを隔離/削除してください。\n"
                      << std::endl;
        } else {
            std::cout << "Emotetは検知されませんでした。\n"
                      << std::endl;
        }
    } else if (GetUserDefaultLangID() == LANG_ID_FR && !IsWindows7()) {
        SetConsoleOutputCP(CP_UTF8);
        // French Report
        if (emotet_processes.size() > 0) {
            for (unsigned int i = 0; i < emotet_processes.size(); ++i) {
                std::cout << "[!!] Emotet"
                          << "\n"
                          << "     Nom du processus: " << emotet_processes[i].process_name << "\n"
                          << "     PID             : " << emotet_processes[i].pid << "\n"
                          << "     Emplacement     : " << emotet_processes[i].image_path << std::endl;
            }
            std::cout << LINE_DELIMITER << std::endl;
            std::cout << "Emotet a été détecté.\n"
                      << "Veuillez supprimer le(s) fichier(s) détecté(s).\n"
                      << std::endl;
        } else {
            std::cout << "Aucune détection.\n"
                      << std::endl;
        }
    } else {
        // English Report
        if (emotet_processes.size() > 0) {
            for (unsigned int i = 0; i < emotet_processes.size(); ++i) {
                std::cout << "[!!] Detected"
                          << "\n"
                          << "     Process Name: " << emotet_processes[i].process_name << "\n"
                          << "     PID         : " << emotet_processes[i].pid << "\n"
                          << "     Image Path  : " << emotet_processes[i].image_path << std::endl;
            }
            std::cout << LINE_DELIMITER << std::endl;
            std::cout << "Emotet was detected.\n"
                      << "Please remove or isolate the suspicious execution file.\n"
                      << std::endl;
        } else {
            std::cout << "No detection.\n"
                      << std::endl;
        }
    }
}

void WriteReport(std::vector<EmotetProcess> emotet_processes, bool is_quiet, std::string output_path) {
    std::string filename;
    char time_file[16];
    char time_iso8601[20];
    wchar_t computer_name[256] = {'\0'};
    unsigned long dword_size = sizeof(computer_name) / sizeof(computer_name[0]);
    std::string hostname;

    if (GetComputerName(computer_name, &dword_size)) {
        hostname = emocheck::WideCharToString(computer_name);
    } else {
        hostname = std::string("");
    }

    time_t t = time(nullptr);
    struct tm local_time;

    localtime_s(&local_time, &t);
    std::strftime(time_iso8601, 20, "%Y-%m-%d %H:%M:%S", &local_time);
    std::strftime(time_file, 16, "%Y%m%d%H%M%S", &local_time);

    if (GetUserDefaultLangID() == LANG_ID_JP && !IsWindows7()) {
        // Japanese Report
        std::cout << "[EmoCheck v" << EMOCHECK_VERSION << "]" << std::endl;
        std::cout << "プログラム実行時刻: " << time_iso8601 << std::endl;
        std::cout << LINE_DELIMITER << std::endl;
        if (emotet_processes.size() > 0) {
            std::cout << "[結果]\n"
                       << "Emotetを検知しました。\n"
                       << std::endl;
            for (unsigned int i = 0; i < emotet_processes.size(); ++i) {
                std::cout << "[詳細]\n"
                           << "     プロセス名    : " << emotet_processes[i].process_name << "\n"
                           << "     プロセスID    : " << emotet_processes[i].pid << "\n"
                           << "     イメージパス  : " << emotet_processes[i].image_path << "\n"
                           << "     レジストリキー: " << emotet_processes[i].run_key << std::endl;
            }
            std::cout << LINE_DELIMITER << std::endl;
            std::cout << "イメージパスの実行ファイルを隔離/削除してください。" << std::endl;
        } else {
            std::cout << "[結果]\n"
                       << "検知しませんでした。" << std::endl;
        }

        if (!is_quiet) {
            std::cout.imbue(std::locale(""));
            std::cout << "以下のファイルに結果を出力しました。" << std::endl;
            std::cout << "\n\t" << filename << "\n"
                      << std::endl;
            std::cout << "ツールのご利用ありがとうございました。\n"
                      << std::endl;
        }
    } else if (GetUserDefaultLangID() == LANG_ID_FR && !IsWindows7()) {
        // French Report
        std::cout << "[EmoCheck v" << EMOCHECK_VERSION << "]" << std::endl;
        std::cout << "Temps d'éxécution: " << time_iso8601 << std::endl;
        std::cout << LINE_DELIMITER << std::endl;
        if (emotet_processes.size() > 0) {
            std::cout << "[Résultat] \nEmotet détecté.\n"
                       << std::endl;
            for (unsigned int i = 0; i < emotet_processes.size(); ++i) {
                std::cout << "[Processus Emotet] \n"
                           << "     Nom du processus: " << emotet_processes[i].process_name << "\n"
                           << "     PID             : " << emotet_processes[i].pid << "\n"
                           << "     Emplacement     : " << emotet_processes[i].image_path << "\n"
                           << "     Clé de registre : " << emotet_processes[i].run_key << std::endl;
            }
            std::cout << LINE_DELIMITER << std::endl;
            std::cout << "Veuillez supprimer le(s) fichier(s) détecté(s)." << std::endl;
        } else {
            std::cout << "[Résultat] \nEmotet n'a pas été détecté." << std::endl;
        }
    } else {
        // English Report
        std::cout << "[EmoCheck v" << EMOCHECK_VERSION << "]" << std::endl;
        std::cout << "Scan time: " << time_iso8601 << std::endl;
        std::cout << LINE_DELIMITER << std::endl;
        if (emotet_processes.size() > 0) {
            std::cout << "[Result] \nDetected Emotet process.\n"
                       << std::endl;
            for (unsigned int i = 0; i < emotet_processes.size(); ++i) {
                std::cout << "[Emotet Process] \n"
                           << "     Process Name  : " << emotet_processes[i].process_name << "\n"
                           << "     Process ID    : " << emotet_processes[i].pid << "\n"
                           << "     Image Path    : " << emotet_processes[i].image_path << "\n"
                           << "     Registry Key  : " << emotet_processes[i].run_key << std::endl;
            }
            std::cout << LINE_DELIMITER << std::endl;
            std::cout << "Please remove or isolate the suspicious execution file." << std::endl;
        } else {
            std::cout << "[Result] \nEmotet was not detected." << std::endl;
        }
    }
}

void JsonReport(std::vector<EmotetProcess> emotet_processes, bool is_quiet, std::string output_path) {
    std::string filename;
    char time_file[16];
    char time_iso8601[20];
    wchar_t computer_name[256] = {'\0'};
    unsigned long dword_size = sizeof(computer_name) / sizeof(computer_name[0]);
    std::string hostname;

    if (GetComputerName(computer_name, &dword_size)) {
        hostname = emocheck::WideCharToString(computer_name);
    } else {
        hostname = std::string("");
    }

    time_t t = time(nullptr);
    struct tm local_time;

    localtime_s(&local_time, &t);
    std::strftime(time_iso8601, 20, "%Y-%m-%d %H:%M:%S", &local_time);
    std::strftime(time_file, 16, "%Y%m%d%H%M%S", &local_time);

    std::cout << "{\n  \"scan_time\":\"" << time_iso8601 << "\",\n"
               << "  \"hostname\":\"" << hostname << "\",\n"
               << "  \"emocheck_version\":\"" << EMOCHECK_VERSION << "\"," << std::endl;
    if (emotet_processes.size() > 0) {
        std::cout  << "  \"is_infected\":\"yes\",\n  \"emotet_processes\":[" << std::endl;
        for (unsigned int i = 0; i < emotet_processes.size(); ++i) {
            std::cout << "    {\n"
                       << "      \"process_name\":\"" << emotet_processes[i].process_name << "\",\n"
                       << "      \"process_id\":\"" << emotet_processes[i].pid << "\",\n"
                       << "      \"image_path\":\"" << EscapeBackSlash(emotet_processes[i].image_path) << "\",\n"
                       << "      \"registry_key\":\"" << EscapeBackSlash(emotet_processes[i].run_key) << "\"" << std::endl;
            if (i == emotet_processes.size() - 1) {
                std::cout << "    }" << std::endl;
            } else {
                std::cout << "    }," << std::endl;
            }
        }
        std::cout << "  ]\n}" << std::endl;
    } else {
        std::cout << "  \"is_infected\":\"no\"\n}" << std::endl;
    }
    return;
}

}  // namespace emocheck

int main(int argc, char *argv[]) {
    std::vector<emocheck::EmotetProcess> scan_result;
    bool is_debug = false;
    bool is_quiet = false;
    bool is_json = false;
    int status;
    std::string output_path = ".";

    if (argc < 2) {
        emocheck::PrintBanner();
        std::tie(status, scan_result) = emocheck::ScanEmotet(is_debug);
        emocheck::PrintReport(scan_result);
        emocheck::WriteReport(scan_result, is_quiet, output_path);
        system("pause");
        return status;
    }

    // Parse parameters
    for (int i = 1; i < argc; i++) {
        if (emocheck::is_param(argv[i])) {
            const char *param = &argv[i][1];
            if (!strcmp(param, PARAM_QUIET)) {
                is_quiet = true;
            } else if (!strcmp(param, PARAM_DEBUG)) {
                // is_debug = true;
            } else if (!strcmp(param, PARAM_JSON)) {
                is_json = true;
            } else if (!strcmp(param, PARAM_HELP)) {
                emocheck::PrintBanner();
                emocheck::PrintHelp();
                return 0;
            } else {
                std::cout << "Invalid parameter: " << param << std::endl;
                return 0;
            }
        } else {
            const char *param = &argv[i][0];
            std::cout << "Invalid parameter: " << param << std::endl;
            return 0;
        }
    }

    if (!is_quiet)
        emocheck::PrintBanner();

    std::tie(status, scan_result) = emocheck::ScanEmotet(is_debug);

    if (!is_quiet)
        emocheck::PrintReport(scan_result);

    if (!is_debug) {
        if (is_json)
            emocheck::JsonReport(scan_result, is_quiet, output_path);
        else
            emocheck::WriteReport(scan_result, is_quiet, output_path);
    }

    if (!is_quiet)
        system("pause");

    return status;
}