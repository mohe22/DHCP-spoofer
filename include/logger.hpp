#pragma once

#include <stdio.h>
#include <mutex>
#include <ctime>
#include <pcap.h>
#include <string.h>

enum LogPriority
{
    TracePriority, DebugPriority, InfoPriority, WarnPriority, ErrorPriority, CriticalPriority
};

class Logger
{
private:
    LogPriority priority = InfoPriority;
    std::mutex logMutex;
    const char* logFilepath = nullptr;
    const char* networkFilepath = nullptr;

    FILE* logFile = nullptr;
    pcap_t* pcapHandle = nullptr;
    pcap_dumper_t* pcapDumper = nullptr;

public:
    static void SetLogPriority(LogPriority newPriority)
    {
        getInstance().priority = newPriority;
    }

    static void EnableLogFileOutput()
    {
        Logger& loggerInstance = getInstance();
        loggerInstance.logFilepath = "general_log.txt";
        loggerInstance.enableLogFile();
    }

    static void EnableLogFileOutput(const char* newFilepath)
    {
        Logger& loggerInstance = getInstance();
        loggerInstance.logFilepath = newFilepath;
        loggerInstance.enableLogFile();
    }

    static void EnableNetworkFileOutput()
    {
        Logger& loggerInstance = getInstance();
        loggerInstance.networkFilepath = "network_log.pcap";
        loggerInstance.enableNetworkFile();
    }

    static void EnableNetworkFileOutput(const char* newFilepath)
    {
        Logger& loggerInstance = getInstance();
        loggerInstance.networkFilepath = newFilepath;
        loggerInstance.enableNetworkFile();
    }

    template<typename... Args>
    static void LogTrace(const char* message, Args... args)
    {
        getInstance().writeLog("[Trace]\t", TracePriority, message, args...);
    }

    template<typename... Args>
    static void LogDebug(const char* message, Args... args)
    {
        getInstance().writeLog("[Debug]\t", DebugPriority, message, args...);
    }

    template<typename... Args>
    static void LogInfo(const char* message, Args... args)
    {
        getInstance().writeLog("[Info]\t", InfoPriority, message, args...);
    }

    template<typename... Args>
    static void LogWarn(const char* message, Args... args)
    {
        getInstance().writeLog("[Warn]\t", WarnPriority, message, args...);
    }

    template<typename... Args>
    static void LogError(const char* message, Args... args)
    {
        getInstance().writeLog("[Error]\t", ErrorPriority, message, args...);
    }

    template<typename... Args>
    static void LogCritical(const char* message, Args... args)
    {
        getInstance().writeLog("[Critical]\t", CriticalPriority, message, args...);
    }



    template<typename... Args>
    static void LogTrace(int line, const char* sourceFile, const char* message, Args... args)
    {
        getInstance().writeLog(line, sourceFile, "[Trace]\t", TracePriority, message, args...);
    }

    template<typename... Args>
    static void LogDebug(int line, const char* sourceFile, const char* message, Args... args)
    {
        getInstance().writeLog(line, sourceFile, "[Debug]\t", DebugPriority, message, args...);
    }

    template<typename... Args>
    static void LogInfo(int line, const char* sourceFile, const char* message, Args... args)
    {
        getInstance().writeLog(line, sourceFile, "[Info]\t", InfoPriority, message, args...);
    }

    template<typename... Args>
    static void LogWarn(int line, const char* sourceFile, const char* message, Args... args)
    {
        getInstance().writeLog(line, sourceFile, "[Warn]\t", WarnPriority, message, args...);
    }

    template<typename... Args>
    static void LogError(int line, const char* sourceFile, const char* message, Args... args)
    {
        getInstance().writeLog(line, sourceFile, "[Error]\t", ErrorPriority, message, args...);
    }

    template<typename... Args>
    static void LogCritical(int line, const char* sourceFile, const char* message, Args... args)
    {
        getInstance().writeLog(line, sourceFile, "[Critical]\t", CriticalPriority, message, args...);
    }

    static void LogNetworkPacket( const unsigned char* packet, size_t packet_len)
    {
        getInstance().writeNetworkPacket(packet, packet_len);
    }

private:
    Logger() {}

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    ~Logger()
    {
        closeLogFile();
        closeNetworkFile();
    }

    static Logger& getInstance()
    {
        static Logger logger;
        return logger;
    }

    template<typename... Args>
    void writeLog(const char* messagePriorityStr, LogPriority messagePriority, const char* message, Args... args)
    {
        if (priority <= messagePriority)
        {
            std::time_t currentTime = std::time(nullptr);
            std::tm* timestamp = std::localtime(&currentTime);
            char buffer[80];
            strftime(buffer, 80, "%c", timestamp);

            std::scoped_lock lock(logMutex);
            printf("%s\t%s", buffer, messagePriorityStr);
            printf(message, args...);
            printf("\n");

            if (logFile)
            {
                fprintf(logFile, "%s\t%s", buffer, messagePriorityStr);
                fprintf(logFile, message, args...);
                fprintf(logFile, "\n");
                fflush(logFile);
            }
        }
    }

    template<typename... Args>
    void writeLog(int lineNumber, const char* sourceFile, const char* messagePriorityStr, LogPriority messagePriority, const char* message, Args... args)
    {
        if (priority <= messagePriority)
        {
            std::time_t currentTime = std::time(nullptr);
            std::tm* timestamp = std::localtime(&currentTime);
            char buffer[80];
            strftime(buffer, 80, "%c", timestamp);

            std::scoped_lock lock(logMutex);
            printf("%s\t%s", buffer, messagePriorityStr);
            printf(message, args...);
            printf(" on line %d in %s\n", lineNumber, sourceFile);

            if (logFile)
            {
                fprintf(logFile, "%s\t%s", buffer, messagePriorityStr);
                fprintf(logFile, message, args...);
                fprintf(logFile, " on line %d in %s\n", lineNumber, sourceFile);
                fflush(logFile);
            }
        }
    }


    void writeNetworkPacket(const unsigned char* packet, size_t packet_len)
    {
        std::scoped_lock lock(logMutex);

        // PCAP packet header
        struct pcap_pkthdr pcap_hdr;
        pcap_hdr.ts.tv_sec = std::time(nullptr);
        pcap_hdr.ts.tv_usec = 0;
        pcap_hdr.caplen = packet_len;
        pcap_hdr.len = packet_len;

        // Write packet to PCAP file
        pcap_dump((u_char*)pcapDumper, &pcap_hdr, packet);
        pcap_dump_flush(pcapDumper);
    }

    bool enableLogFile()
    {
        closeLogFile();
        logFile = fopen(logFilepath, "a");
        return logFile != nullptr;
    }

    bool enableNetworkFile()
    {
        closeNetworkFile();
        char errbuf[PCAP_ERRBUF_SIZE];
        pcapHandle = pcap_open_dead(DLT_EN10MB, 65535); // Ethernet link-layer, max packet size
        if (!pcapHandle)
        {
            fprintf(stderr, "Failed to open PCAP handle\n");
            return false;
        }
        pcapDumper = pcap_dump_open(pcapHandle, networkFilepath);
        if (!pcapDumper)
        {
            fprintf(stderr, "Failed to open PCAP file: %s\n", errbuf);
            pcap_close(pcapHandle);
            pcapHandle = nullptr;
            return false;
        }
        return true;
    }

    void closeLogFile()
    {
        if (logFile)
        {
            fclose(logFile);
            logFile = nullptr;
        }
    }

    void closeNetworkFile()
    {
        if (pcapDumper)
        {
            pcap_dump_close(pcapDumper);
            pcapDumper = nullptr;
        }
        if (pcapHandle)
        {
            pcap_close(pcapHandle);
            pcapHandle = nullptr;
        }
    }
};

#define LOG_TRACE(Message, ...) (Logger::LogTrace(__LINE__, __FILE__, Message, ##__VA_ARGS__))
#define LOG_DEBUG(Message, ...) (Logger::LogDebug(__LINE__, __FILE__, Message, ##__VA_ARGS__))
#define LOG_INFO(Message, ...) (Logger::LogInfo(__LINE__, __FILE__, Message, ##__VA_ARGS__))
#define LOG_WARN(Message, ...) (Logger::LogWarn(__LINE__, __FILE__, Message, ##__VA_ARGS__))
#define LOG_ERROR(Message, ...) (Logger::LogError(__LINE__, __FILE__, Message, ##__VA_ARGS__))
#define LOG_CRITICAL(Message, ...) (Logger::LogCritical(__LINE__, __FILE__, Message, ##__VA_ARGS__))
#define LOG_NETWORK_PACKET(Packet, PacketLen) \
    (Logger::LogNetworkPacket(Packet, PacketLen))
