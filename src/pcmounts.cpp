
#include <fcntl.h>
#include <mntent.h>
#include <sys/stat.h>

#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

constexpr char NColor[] = "\033[0m";
constexpr char SColor[] = "\033[92m";
constexpr char EColor[] = "\033[91m";
constexpr char MColor[] = "\033[95m";
constexpr char TColor[] = "\033[94m";

constexpr int NO_CHECK_UP = 1;
constexpr int RET_FAILED = -1;
constexpr int RET_SUCCEEDED = 0;
constexpr int ALERT_MOUNT_POINT_NOT_EXISTS = 10;
constexpr int ALERT_MOUNT_POINT_NOT_MOUNTED = 20;
constexpr int ALERT_DIRECTORY_NOT_EXISTS = 30;
constexpr int ALERT_DIRECTORY_INACTIVE_READ = 40;
constexpr int ALERT_DIRECTORY_INACTIVE_WRITE = 50;

inline string eVal(const auto& paramVal) {
  ostringstream ost;
  ost << EColor;
  ost << paramVal;
  ost << NColor;
  return ost.str();
}

inline string sVal(const auto& paramVal) {
  ostringstream ost;
  ost << SColor;
  ost << paramVal;
  ost << NColor;
  return ost.str();
}

inline string mVal(const auto& paramVal) {
  ostringstream ost;
  ost << MColor;
  ost << paramVal;
  ost << NColor;
  return ost.str();
}

void oLog(const string& logStr, const char* paramVal = nullptr) {
  auto now = chrono::time_point_cast<chrono::milliseconds>(
      chrono::current_zone()->to_local(chrono::system_clock::now()));
  if (paramVal != nullptr) {
    auto repIndex = logStr.find("{}");
    if (repIndex != string::npos) {
      string pa;
      pa += logStr.substr(0, repIndex);
      pa += paramVal;
      pa += logStr.substr(repIndex + 2, logStr.length());
      cout << TColor << format("{:%T}", now) << NColor << " : " << pa << endl;
    }
  } else
    cout << TColor << format("{:%T}", now) << NColor << " : " << logStr << endl;
}

struct PCMConfigFolder {
  string pathMountPoint;
  string pathDirectory;
  string pastTime;
  string mntType;
  string timeUnit;
  bool pathMountPointExists;
  bool pathMountPointIsMounted;
  bool pathExists;
  bool pastPathAccessRead;
  bool pastPathAccesWrite;
  int lastAccessWriteTimeInSeconds;
  int lastAccessReadTimeInSeconds;
};

struct PCMConfig {
  vector<PCMConfigFolder> includes;
  string configFile;
  string alertMail;
  string alertServer;
  bool verboseOn;
};

struct mntent* mountPoint(const char* filename, struct mntent* mnt) {
  struct stat s;
  FILE* fp = nullptr;
  dev_t dev;
  if (stat(filename, &s) != 0) {
    return nullptr;
  }
  dev = s.st_dev;
  if ((fp = setmntent("/proc/mounts", "r")) == nullptr) {
    return nullptr;
  }
  char buf[1024];
  while (getmntent_r(fp, mnt, buf, sizeof(buf))) {
    if (stat(mnt->mnt_dir, &s) != 0) {
      continue;
    }
    if (s.st_dev == dev) {
      endmntent(fp);
      return mnt;
    }
  }
  endmntent(fp);
  return nullptr;
}

void checkMount(auto& pcmFolder, int& oMountExists, int& oMountIsMounted) {
  oMountExists = NO_CHECK_UP;
  oMountIsMounted = NO_CHECK_UP;
  if (pcmFolder.pathMountPointExists) {
    if (pcmFolder.pathMountPoint == "" ||
        filesystem::exists(pcmFolder.pathMountPoint) == false) {
      oMountExists = ALERT_MOUNT_POINT_NOT_EXISTS;
    } else {
      oMountExists = RET_SUCCEEDED;
    }
  }
  if (pcmFolder.pathMountPointIsMounted) {
    mntent mpIn;
    auto mp = mountPoint(pcmFolder.pathMountPoint.c_str(), &mpIn);
    if (mp == nullptr) oMountIsMounted = ALERT_MOUNT_POINT_NOT_MOUNTED;
    pcmFolder.mntType = mp->mnt_type;
    oMountIsMounted = RET_SUCCEEDED;
  }
}

void checkPastAccessTime(const string& directory, PCMConfigFolder& pcmFolder,
                         int& inARange, int& inMRange) {
  double secondsPerDay = 86400;
  double secondsPerHour = 3600;
  struct stat s;
  struct statx stx;
  ostringstream ost;
  ost << pcmFolder.pathMountPoint;
  ost << pcmFolder.pathDirectory;
  string checkTimeValue =
      pcmFolder.pastTime.substr(0, pcmFolder.pastTime.length() - 1);
  pcmFolder.timeUnit =
      pcmFolder.pastTime.substr(pcmFolder.pastTime.length() - 1, 1);
  double ConfiguredCheckPastTimeInSeconds = 0.0;
  if (pcmFolder.timeUnit == "d")
    ConfiguredCheckPastTimeInSeconds = secondsPerDay * stoi(checkTimeValue);
  else if (pcmFolder.timeUnit == "h")
    ConfiguredCheckPastTimeInSeconds = secondsPerHour * stoi(checkTimeValue);
  time_t now;
  time(&now);
  if (pcmFolder.mntType == "cifs") {
    unsigned int mask = STATX_ATIME | STATX_MTIME;
    memset(&stx, 0xbf, sizeof(stx));
    if (statx(AT_FDCWD, directory.c_str(),
              AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_STATX_DONT_SYNC, mask,
              &stx) != 0) {
      inARange = RET_FAILED;
      inMRange = RET_FAILED;
    } else {
      auto secondsSinceLastAccess = difftime(now, stx.stx_atime.tv_sec);
      if (secondsSinceLastAccess > ConfiguredCheckPastTimeInSeconds)
        inARange = ALERT_DIRECTORY_INACTIVE_READ;
      else
        inARange = RET_SUCCEEDED;
      auto secondsSinceLastModification = difftime(now, stx.stx_mtime.tv_sec);
      if (secondsSinceLastModification > ConfiguredCheckPastTimeInSeconds)
        inMRange = ALERT_DIRECTORY_INACTIVE_WRITE;
      else
        inMRange = RET_SUCCEEDED;
      pcmFolder.lastAccessReadTimeInSeconds = secondsSinceLastAccess;
      pcmFolder.lastAccessWriteTimeInSeconds = secondsSinceLastModification;
    }
  } else {
    if (stat(directory.c_str(), &s) != 0) {
      inARange = RET_FAILED;
      inMRange = RET_FAILED;
    } else {
      auto secondsSinceLastAccess = difftime(now, s.st_atime);
      if (secondsSinceLastAccess > ConfiguredCheckPastTimeInSeconds)
        inARange = ALERT_DIRECTORY_INACTIVE_READ;
      else
        inARange = RET_SUCCEEDED;
      auto secondsSinceLastModification = difftime(now, s.st_mtime);
      if (secondsSinceLastModification > ConfiguredCheckPastTimeInSeconds)
        inMRange = ALERT_DIRECTORY_INACTIVE_WRITE;
      else
        inMRange = RET_SUCCEEDED;
      pcmFolder.lastAccessReadTimeInSeconds = secondsSinceLastAccess;
      pcmFolder.lastAccessWriteTimeInSeconds = secondsSinceLastModification;
    }
  }
}

void checkDirectory(auto& pcmFolder, int& dirExists, int& dirAccessOutOfRange,
                    int& dirModifcationOutOfRange) {
  dirExists = NO_CHECK_UP;
  dirAccessOutOfRange = NO_CHECK_UP;
  dirModifcationOutOfRange = NO_CHECK_UP;
  ostringstream ost;
  ost << pcmFolder.pathMountPoint;
  ost << pcmFolder.pathDirectory;
  if (pcmFolder.pathExists) {
    if (filesystem::exists(ost.str()) == false) {
      dirExists = ALERT_DIRECTORY_NOT_EXISTS;
    } else
      dirExists = RET_SUCCEEDED;
  }
  int isInPastAccessTimeRange = NO_CHECK_UP;
  int isInPastModificationTimeRange = NO_CHECK_UP;
  checkPastAccessTime(ost.str(), pcmFolder, isInPastAccessTimeRange,
                      isInPastModificationTimeRange);
  if (pcmFolder.pastPathAccessRead) {
    dirAccessOutOfRange = isInPastAccessTimeRange;
  }
  if (pcmFolder.pastPathAccesWrite) {
    dirModifcationOutOfRange = isInPastModificationTimeRange;
  }
}

int runChecks(PCMConfig& pcmConfig) {
  oLog("   runChecks Begin");
  int lastError = RET_SUCCEEDED;
  for (auto& incFolder : pcmConfig.includes) {
    int mountPathExists = 0;
    int mountIsMounted = 0;
    checkMount(incFolder, mountPathExists, mountIsMounted);
    int dirExists = 0;
    int dirAccessOutOfRange = 0;
    int dirModifcationOutOfRange = 0;
    checkDirectory(incFolder, dirExists, dirAccessOutOfRange,
                   dirModifcationOutOfRange);
    if (lastError == RET_SUCCEEDED) {
      if (mountPathExists > NO_CHECK_UP) lastError = mountPathExists;
      if (lastError == RET_SUCCEEDED && mountIsMounted > NO_CHECK_UP)
        lastError = mountIsMounted;
    }
    if (lastError == RET_SUCCEEDED) {
      if (dirExists > NO_CHECK_UP) lastError = dirExists;
      if (lastError == RET_SUCCEEDED && dirAccessOutOfRange > NO_CHECK_UP)
        lastError = dirAccessOutOfRange;
      if (lastError == RET_SUCCEEDED && dirModifcationOutOfRange > NO_CHECK_UP)
        lastError = dirModifcationOutOfRange;
    }
    ostringstream ost;
    ost << "      ";
    ost << "[ME:";
    ost << (mountPathExists == NO_CHECK_UP ? " "
            : mountPathExists == ALERT_MOUNT_POINT_NOT_EXISTS
                ? "\033[91mF\033[0m"
                : "\033[92mT\033[0m");
    ost << "|";
    ost << "MM:";
    ost << (mountIsMounted == NO_CHECK_UP ? " "
            : mountIsMounted == ALERT_MOUNT_POINT_NOT_MOUNTED
                ? "\033[91mF\033[0m"
                : "\033[92mT\033[0m");
    if (pcmConfig.verboseOn) {
      ost << "(" << setw(6) << setfill('.') << incFolder.mntType << ")";
    }
    ost << "|";
    ost << "DE:";
    ost << (dirExists == NO_CHECK_UP                  ? " "
            : dirExists == ALERT_DIRECTORY_NOT_EXISTS ? "\033[91mF\033[0m"
                                                      : "\033[92mT\033[0m");
    ost << "|";
    ost << "DR:";
    ost << (dirAccessOutOfRange == NO_CHECK_UP ? " "
            : dirAccessOutOfRange == ALERT_DIRECTORY_INACTIVE_READ
                ? "\033[91mF\033[0m"
                : "\033[92mT\033[0m");
    if (pcmConfig.verboseOn) {
      if (dirAccessOutOfRange != NO_CHECK_UP) {
        std::chrono::hh_mm_ss time{
            std::chrono::seconds(incFolder.lastAccessReadTimeInSeconds)};
        ost << "(" << setw(5) << setfill('0') << time.hours().count() << ":"
            << setw(2) << setfill('0') << time.minutes().count() << ":"
            << setw(2) << setfill('0') << time.seconds().count() << ")";
      } else
        ost << "             ";
    }
    ost << "|";
    ost << "DW:";
    ost << (dirModifcationOutOfRange == NO_CHECK_UP ? " "
            : dirModifcationOutOfRange == ALERT_DIRECTORY_INACTIVE_WRITE
                ? "\033[91mF\033[0m"
                : "\033[92mT\033[0m");
    if (pcmConfig.verboseOn) {
      if (dirModifcationOutOfRange != NO_CHECK_UP) {
        std::chrono::hh_mm_ss time{
            std::chrono::seconds(incFolder.lastAccessWriteTimeInSeconds)};
        ost << "(" << setw(5) << setfill('0') << time.hours().count() << ":"
            << setw(2) << setfill('0') << time.minutes().count() << ":"
            << setw(2) << setfill('0') << time.seconds().count() << ")";
      } else
        ost << "             ";
    }
    ost << "]";
    ost << "[";
    ost << MColor;
    ost << incFolder.pathMountPoint;
    ost << TColor;
    ost << incFolder.pathDirectory;
    ost << NColor;
    ost << "]";
    oLog(ost.str());
  }
  oLog("   runChecks Completed");
  return lastError;
}

void printConfig(PCMConfig& pcmConfig) {
  oLog("   configFile: {}", pcmConfig.configFile.c_str());
  oLog("    verboseOn: {}", pcmConfig.verboseOn ? "True" : "False");
  oLog("    alertMail: {}", pcmConfig.alertMail.c_str());
  oLog("  alertServer: {}", pcmConfig.alertServer.c_str());
  for (auto& incFol : pcmConfig.includes) {
    oLog("");
    oLog("      include:              MountPoint: {}",
         incFol.pathMountPoint.c_str());
    oLog("      include:               Directory: {}",
         incFol.pathDirectory.c_str());
    oLog("      include:                PastTime: {}", incFol.pastTime.c_str());
    oLog("      include:        alertMountExists: {}",
         incFol.pathMountPointExists ? "True" : "False");
    oLog("      include:     alertMountIsMounted: {}",
         incFol.pathMountPointIsMounted ? "True" : "False");
    oLog("      include:    alertDirectoryExists: {}",
         incFol.pathExists ? "True" : "False");
    oLog("      include:  alertDirectoryPastRead: {}",
         incFol.pastPathAccessRead ? "True" : "False");
    oLog("      include: alertDirectoryPastWrite: {}",
         incFol.pastPathAccesWrite ? "True" : "False");
  }
  oLog("");
}

void printArguments() {
  oLog("pcmounts -c:<configFile> | Needed ");
  oLog("         -v              | Optional VerboseOn ");
  oLog("         -h              | Print this help");
}

void parseConfig(PCMConfig& pcmConfig) {
  std::ifstream cnfFile(pcmConfig.configFile);
  std::string configLine;
  while (std::getline(cnfFile, configLine)) {
    if (configLine.find("include:") != string::npos) {
      PCMConfigFolder pcmConfigFolder;
      string incata =
          configLine.substr(configLine.find("{") + 1, configLine.find("}"));
      std::regex regEx{","};
      std::sregex_token_iterator start{incata.begin(), incata.end(), regEx, -1},
          end;
      std::vector<string> includeItems{start, end};
      if (includeItems.size() == 8) {
        pcmConfigFolder.pathMountPoint =
            includeItems[0].substr(1, includeItems[0].rfind("\"") - 1);
        pcmConfigFolder.pathDirectory =
            includeItems[1].substr(1, includeItems[1].rfind("\"") - 1);
        pcmConfigFolder.pastTime =
            includeItems[7].substr(1, includeItems[7].rfind("\"") - 1);
        pcmConfigFolder.pathMountPointExists = includeItems[2] == "1";
        pcmConfigFolder.pathMountPointIsMounted = includeItems[3] == "1";
        pcmConfigFolder.pathExists = includeItems[4] == "1";
        pcmConfigFolder.pastPathAccessRead = includeItems[5] == "1";
        ;
        pcmConfigFolder.pastPathAccesWrite = includeItems[6] == "1";
        pcmConfig.includes.push_back(pcmConfigFolder);
      }
    }
    if (configLine.find("alertmail:") != string::npos) {
      pcmConfig.alertMail =
          regex_replace(configLine.substr(10, configLine.size()),
                        regex("(^[ ]+)|([ ]+$)"), "");
    }
    if (configLine.find("alertserver:") != string::npos) {
      pcmConfig.alertServer =
          regex_replace(configLine.substr(12, configLine.size()),
                        regex("(^[ ]+)|([ ]+$)"), "");
    }
  }
}

PCMConfig readConfig(int argCount, char** argValues) {
  PCMConfig resultConfig;
  resultConfig.verboseOn = false;
  for (auto i = 1; i < argCount; ++i) {
    string argument{argValues[i]};
    if (argument.substr(0, 3) == "-c:") {
      resultConfig.configFile = argument.substr(3, argument.size());
    }
    if (argument.substr(0, 2) == "-v") {
      resultConfig.verboseOn = true;
    }
    if ((argument.substr(0, 2) == "-h")) {
      printArguments();
      oLog("PastCheckMounts Completed Failed (0)");
      exit(0);
    }
  }
  if (resultConfig.configFile == "") throw invalid_argument("No given config!");
  if (!filesystem::exists(resultConfig.configFile)) {
    ostringstream ost;
    ost << "Given configFile: '" << resultConfig.configFile
        << "' doesn't exists!";
    throw invalid_argument(ost.str());
  }
  parseConfig(resultConfig);
  return resultConfig;
}

int main(int argCount, char** argValues) {
  int Result = RET_FAILED;
  oLog("PastCheckMounts Begin");
  try {
    auto config = readConfig(argCount, argValues);
    if (config.verboseOn) printConfig(config);
    Result = runChecks(config);
    if (Result == RET_SUCCEEDED)
      oLog("PastCheckMounts Completed Succeeded ({})",
           to_string(Result).c_str());
    else
      oLog("PastCheckMounts Completed Failed ({})", to_string(Result).c_str());
    return Result;
  } catch (invalid_argument const& ex) {
    oLog(ex.what());
    oLog("PastCheckMounts Completed Failed ({})", to_string(Result).c_str());
    return Result;
  } catch (...) {
    oLog("PastCheckMounts Completed Failed ({})", to_string(Result).c_str());
    return Result;
  }
}
