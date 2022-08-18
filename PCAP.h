#pragma once

#include <string>
#include <cstdint>


class PCAPReader {
private:
    const std::string m_fileName;


public:
    explicit PCAPReader(const std::string &fileName);

	~PCAPReader();

    // Количество пакетов в файле
    uint64_t packetsCount() const;

    // Общий объём полезной нагрузки (без учёта заголовков)
    uint64_t payloadSize() const;

};