/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** test_ProtocolDetector
*/

#include <criterion/criterion.h>
#include "analysis/ProtocolDetector.hpp"
#include <string>
#include <vector>

using namespace analyser;

static const std::string CLIENT = "192.168.1.10";
static const std::string SERVER = "192.168.1.20";

static std::vector<std::uint8_t> bytes(const std::string &text)
{
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

static LogEntry packet(const std::string &protocol, const std::string &source, std::uint16_t sourcePort,
    const std::string &destination, std::uint16_t destinationPort,
    const std::vector<std::uint8_t> &payload = {}, const std::optional<std::string> &flags = std::nullopt)
{
    LogEntry entry;

    entry.timestampSeconds = 10.0;
    entry.sizeBytes = 54 + payload.size();
    entry.protocol = protocol;
    entry.sourceIp = source;
    entry.sourcePort = sourcePort;
    entry.destinationIp = destination;
    entry.destinationPort = destinationPort;
    entry.payloadSize = payload.size();
    entry.payload = payload;
    entry.tcpFlags = flags;
    return entry;
}

// Handshake then the first data packet of the client, returns the alert of the data packet
static std::optional<ProtocolMismatchAlert> tcpConnection(ProtocolDetector &detector, std::uint16_t port,
    const std::vector<std::uint8_t> &payload, std::uint16_t clientPort = 50000)
{
    cr_assert_not(detector.addPacket(packet("TCP", CLIENT, clientPort, SERVER, port, {}, "[SYN]")));
    cr_assert_not(detector.addPacket(packet("TCP", SERVER, port, CLIENT, clientPort, {}, "[SYN, ACK]")));
    cr_assert_not(detector.addPacket(packet("TCP", CLIENT, clientPort, SERVER, port, {}, "[ACK]")));
    return detector.addPacket(packet("TCP", CLIENT, clientPort, SERVER, port, payload, "[PSH, ACK]"));
}

static const std::vector<std::uint8_t> TLS_CLIENT_HELLO = {0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc};

// ===== port table =====

Test(ProtocolDetector, expected_protocol_table)
{
    cr_assert_eq(*ProtocolDetector::expectedProtocol("TCP", 80), Protocol::Http);
    cr_assert_eq(*ProtocolDetector::expectedProtocol("TCP", 8080), Protocol::Http);
    cr_assert_eq(*ProtocolDetector::expectedProtocol("TCP", 443), Protocol::Tls);
    cr_assert_eq(*ProtocolDetector::expectedProtocol("TCP", 8443), Protocol::Tls);
    cr_assert_eq(*ProtocolDetector::expectedProtocol("TCP", 465), Protocol::Tls);
    cr_assert_eq(*ProtocolDetector::expectedProtocol("TCP", 993), Protocol::Tls);
    cr_assert_eq(*ProtocolDetector::expectedProtocol("TCP", 995), Protocol::Tls);
    cr_assert_eq(*ProtocolDetector::expectedProtocol("TCP", 22), Protocol::Ssh);
}

Test(ProtocolDetector, expected_protocol_depends_on_transport)
{
    cr_assert_not(ProtocolDetector::expectedProtocol("UDP", 443).has_value(), "QUIC, not TLS");
    cr_assert_not(ProtocolDetector::expectedProtocol("UDP", 80).has_value());
    cr_assert_not(ProtocolDetector::expectedProtocol("TCP", 50000).has_value());
    cr_assert_not(ProtocolDetector::expectedProtocol("ICMP", 0).has_value());
}

Test(ProtocolDetector, expected_protocol_weak_signatures_not_in_table)
{
    cr_assert_not(ProtocolDetector::expectedProtocol("UDP", 53).has_value(), "DNS");
    cr_assert_not(ProtocolDetector::expectedProtocol("TCP", 53).has_value(), "DNS over TCP");
    cr_assert_not(ProtocolDetector::expectedProtocol("UDP", 123).has_value(), "NTP");
}

Test(ProtocolDetector, expected_protocol_empty_transport)
{
    cr_assert_not(ProtocolDetector::expectedProtocol("", 0).has_value(), "no default entry in the table");
}

Test(ProtocolDetector, names)
{
    cr_assert_eq(ProtocolDetector::name(Protocol::Http), "HTTP");
    cr_assert_eq(ProtocolDetector::name(Protocol::Tls), "TLS");
    cr_assert_eq(ProtocolDetector::name(Protocol::Ssh), "SSH");
    cr_assert_eq(ProtocolDetector::name(Protocol::Unknown), "unknown");
}

// ===== signatures =====

Test(ProtocolDetector, http_signatures)
{
    for (const char *start : {"GET / HTTP/1.1\r\n", "POST /login HTTP/1.1\r\n", "HEAD / HTTP/1.0\r\n",
            "OPTIONS * HTTP/1.1\r\n", "HTTP/1.1 200 OK\r\n", "HTTP/1.0 404 Not Found\r\n",
            "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"})
        cr_assert(ProtocolDetector::matches(Protocol::Http, bytes(start)), "%s", start);
    cr_assert_not(ProtocolDetector::matches(Protocol::Http, bytes("hello world\n")));
    cr_assert_not(ProtocolDetector::matches(Protocol::Http, bytes("get / http/1.1")),
        "methods are case sensitive");
    cr_assert_not(ProtocolDetector::matches(Protocol::Http, bytes("GET")));
    cr_assert_not(ProtocolDetector::matches(Protocol::Http, {}));
}

Test(ProtocolDetector, tls_signatures)
{
    cr_assert(ProtocolDetector::matches(Protocol::Tls, TLS_CLIENT_HELLO));
    cr_assert(ProtocolDetector::matches(Protocol::Tls, {0x17, 0x03, 0x03, 0x00, 0x20}),
        "application data");
    cr_assert(ProtocolDetector::matches(Protocol::Tls, {0x15, 0x03, 0x03}), "alert");
    cr_assert_not(ProtocolDetector::matches(Protocol::Tls, {0x18, 0x03, 0x03}), "bad type");
    cr_assert_not(ProtocolDetector::matches(Protocol::Tls, {0x16, 0x02, 0x00}), "bad version");
    cr_assert_not(ProtocolDetector::matches(Protocol::Tls, {0x16, 0x03, 0x05}), "bad minor");
    cr_assert_not(ProtocolDetector::matches(Protocol::Tls, {0x16, 0x03}), "too short");
    cr_assert_not(ProtocolDetector::matches(Protocol::Tls, bytes("GET / HTTP/1.1")));
}

Test(ProtocolDetector, ssh_signatures)
{
    cr_assert(ProtocolDetector::matches(Protocol::Ssh, bytes("SSH-2.0-OpenSSH_9.6\r\n")));
    cr_assert(ProtocolDetector::matches(Protocol::Ssh, bytes("SSH-1.99-old\r\n")));
    cr_assert_not(ProtocolDetector::matches(Protocol::Ssh, bytes("SSH")));
    cr_assert_not(ProtocolDetector::matches(Protocol::Ssh, bytes("ssh-2.0-x")));
}

Test(ProtocolDetector, unknown_never_matches)
{
    cr_assert_not(ProtocolDetector::matches(Protocol::Unknown, bytes("anything")));
    cr_assert_not(ProtocolDetector::matches(Protocol::Unknown, bytes("GET / HTTP/1.1\r\n")));
}

Test(ProtocolDetector, signatures_do_not_overlap)
{
    cr_assert_not(ProtocolDetector::matches(Protocol::Http, TLS_CLIENT_HELLO));
    cr_assert_not(ProtocolDetector::matches(Protocol::Http, bytes("SSH-2.0-OpenSSH_9.6\r\n")));
    cr_assert_not(ProtocolDetector::matches(Protocol::Ssh, TLS_CLIENT_HELLO));
    cr_assert_not(ProtocolDetector::matches(Protocol::Ssh, bytes("GET / HTTP/1.1\r\n")));
    cr_assert_not(ProtocolDetector::matches(Protocol::Tls, bytes("SSH-2.0-OpenSSH_9.6\r\n")));
}

Test(ProtocolDetector, detect_signatures)
{
    cr_assert_eq(ProtocolDetector::detect(TLS_CLIENT_HELLO), Protocol::Tls);
    cr_assert_eq(ProtocolDetector::detect(bytes("SSH-2.0-OpenSSH_9.6\r\n")), Protocol::Ssh);
    cr_assert_eq(ProtocolDetector::detect(bytes("GET / HTTP/1.1\r\n")), Protocol::Http);
    cr_assert_eq(ProtocolDetector::detect(bytes("HTTP/1.1 200 OK\r\n")), Protocol::Http);
    cr_assert_eq(ProtocolDetector::detect(bytes("hello world\n")), Protocol::Unknown);
    cr_assert_eq(ProtocolDetector::detect({0xa2, 0x8d, 0x01, 0x00, 0x00, 0x01}), Protocol::Unknown, "binary");
    cr_assert_eq(ProtocolDetector::detect({}), Protocol::Unknown);
}

// ===== TCP connections =====

Test(ProtocolDetector, raw_text_on_port_80)
{
    ProtocolDetector detector;
    std::optional<ProtocolMismatchAlert> alert = tcpConnection(detector, 80, bytes("hello world\n"));

    cr_assert(alert.has_value());
    cr_assert_float_eq(alert->timestampSeconds, 10.0, 1e-9);
    cr_assert_eq(alert->sourceIp, CLIENT);
    cr_assert_eq(alert->sourcePort, 50000);
    cr_assert_eq(alert->destinationIp, SERVER);
    cr_assert_eq(alert->destinationPort, 80);
    cr_assert_eq(alert->transport, "TCP");
    cr_assert_eq(alert->servicePort, 80);
    cr_assert_eq(alert->expected, Protocol::Http);
    cr_assert_eq(alert->detected, Protocol::Unknown);
    cr_assert_eq(alert->payloadSize, 12);
    cr_assert_eq(alert->preview.size(), ProtocolDetector::previewBytes);
    cr_assert_eq(alert->preview[0], 'h');
}

Test(ProtocolDetector, valid_protocols_do_not_alert)
{
    ProtocolDetector detector;

    cr_assert_not(tcpConnection(detector, 80, bytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n")).has_value());
    cr_assert_not(tcpConnection(detector, 443, TLS_CLIENT_HELLO, 50001).has_value());
    cr_assert_not(tcpConnection(detector, 22, bytes("SSH-2.0-OpenSSH_9.6\r\n"), 50002).has_value());
}

Test(ProtocolDetector, other_protocol_is_detected)
{
    ProtocolDetector detector;
    std::optional<ProtocolMismatchAlert> ssh = tcpConnection(detector, 443, bytes("SSH-2.0-OpenSSH_9.6\r\n"));
    std::optional<ProtocolMismatchAlert> http = tcpConnection(detector, 22, bytes("GET / HTTP/1.1\r\n"), 50001);

    cr_assert(ssh.has_value());
    cr_assert_eq(ssh->expected, Protocol::Tls);
    cr_assert_eq(ssh->detected, Protocol::Ssh);
    cr_assert(http.has_value());
    cr_assert_eq(http->expected, Protocol::Ssh);
    cr_assert_eq(http->detected, Protocol::Http);
}

Test(ProtocolDetector, server_side_first_data)
{
    ProtocolDetector detector;

    // the server speaks first (banner): the service port is the source port
    cr_assert_not(detector.addPacket(packet("TCP", CLIENT, 50000, SERVER, 80, {}, "[SYN]")));
    cr_assert_not(detector.addPacket(packet("TCP", SERVER, 80, CLIENT, 50000, {}, "[SYN, ACK]")));
    std::optional<ProtocolMismatchAlert> alert = detector.addPacket(
        packet("TCP", SERVER, 80, CLIENT, 50000, bytes("raw banner\n"), "[PSH, ACK]"));

    cr_assert(alert.has_value());
    cr_assert_eq(alert->servicePort, 80);
    cr_assert_eq(alert->sourcePort, 80);
}

Test(ProtocolDetector, only_first_data_of_each_direction)
{
    ProtocolDetector detector;

    cr_assert_not(tcpConnection(detector, 80, bytes("GET / HTTP/1.1\r\n")).has_value());
    // body of the request: arbitrary bytes, not checked
    cr_assert_not(detector.addPacket(packet("TCP", CLIENT, 50000, SERVER, 80, bytes("{\"a\":1}"), "[PSH, ACK]")));
    // first data of the server: checked
    cr_assert_not(detector.addPacket(packet("TCP", SERVER, 80, CLIENT, 50000, bytes("HTTP/1.1 200 OK\r\n"),
        "[PSH, ACK]")));
    cr_assert_not(detector.addPacket(packet("TCP", SERVER, 80, CLIENT, 50000, bytes("<html>"), "[PSH, ACK]")));
}

Test(ProtocolDetector, connection_without_syn_is_ignored)
{
    ProtocolDetector detector;

    // opened before the capture: the first segment seen is in the middle of the stream
    cr_assert_not(detector.addPacket(packet("TCP", CLIENT, 50000, SERVER, 80, bytes("hello\n"), "[PSH, ACK]")));
    cr_assert_not(detector.addPacket(packet("TCP", SERVER, 443, CLIENT, 50001, bytes("garbage"), "[ACK]")));
}

Test(ProtocolDetector, empty_segments_are_skipped)
{
    ProtocolDetector detector;

    cr_assert_not(detector.addPacket(packet("TCP", CLIENT, 50000, SERVER, 80, {}, "[SYN]")));
    for (int i = 0; i < 5; i++)
        cr_assert_not(detector.addPacket(packet("TCP", CLIENT, 50000, SERVER, 80, {}, "[ACK]")));
    cr_assert(detector.addPacket(packet("TCP", CLIENT, 50000, SERVER, 80, bytes("hello\n"), "[PSH, ACK]")),
        "pure ACKs do not consume the first data");
}

Test(ProtocolDetector, closed_connection_is_forgotten)
{
    ProtocolDetector detector;

    cr_assert_not(detector.addPacket(packet("TCP", CLIENT, 50000, SERVER, 80, {}, "[SYN]")));
    cr_assert_not(detector.addPacket(packet("TCP", CLIENT, 50000, SERVER, 80, {}, "[RST]")));
    cr_assert_not(detector.addPacket(packet("TCP", CLIENT, 50000, SERVER, 80, bytes("hello\n"), "[PSH, ACK]")));
}

Test(ProtocolDetector, port_not_in_table_is_ignored)
{
    ProtocolDetector detector;

    cr_assert_not(tcpConnection(detector, 5000, bytes("hello\n")).has_value());
    cr_assert_not(tcpConnection(detector, 53, bytes("hello\n"), 50001).has_value(), "DNS over TCP not checked");
}

Test(ProtocolDetector, reported_once_per_service_and_client)
{
    ProtocolDetector detector;

    cr_assert(tcpConnection(detector, 80, bytes("hello\n"), 50000).has_value());
    cr_assert_not(tcpConnection(detector, 80, bytes("hello again\n"), 50001).has_value(),
        "same client, same service, new connection");
    cr_assert(tcpConnection(detector, 8080, bytes("hello\n"), 50002).has_value(), "other service");
}

Test(ProtocolDetector, duplicated_packets)
{
    ProtocolDetector detector;
    LogEntry data = packet("TCP", CLIENT, 50000, SERVER, 80, bytes("GET / HTTP/1.1\r\n"), "[PSH, ACK]");

    // loopback captures some packets twice
    cr_assert_not(detector.addPacket(packet("TCP", CLIENT, 50000, SERVER, 80, {}, "[SYN]")));
    cr_assert_not(detector.addPacket(packet("TCP", CLIENT, 50000, SERVER, 80, {}, "[SYN]")));
    cr_assert_not(detector.addPacket(data));
    cr_assert_not(detector.addPacket(data));
}

// ===== UDP =====

Test(ProtocolDetector, udp_is_not_checked)
{
    ProtocolDetector detector;

    // no UDP port in the table: DNS (53) and NTP (123) signatures are not reliable, UDP 443 is QUIC
    for (int port : {53, 80, 123, 443, 8080}) {
        cr_assert_not(detector.addPacket(packet("UDP", CLIENT, 40000, SERVER, port, bytes("hello world\n"))),
            "request to UDP port %d", port);
        cr_assert_not(detector.addPacket(packet("UDP", SERVER, port, CLIENT, 40000, bytes("hello world\n"))),
            "reply from UDP port %d", port);
    }
}

Test(ProtocolDetector, udp_without_payload)
{
    ProtocolDetector detector;

    cr_assert_not(detector.addPacket(packet("UDP", CLIENT, 40000, SERVER, 53)), "no payload (minimum log)");
    cr_assert_not(detector.addPacket(packet("UDP", CLIENT, 40000, SERVER, 80)));
}

Test(ProtocolDetector, ignores_non_ip_records)
{
    ProtocolDetector detector;

    cr_assert_not(detector.addPacket(packet("", "", 0, "", 0, bytes("hello"))));
    cr_assert_not(detector.addPacket(packet("ICMP", CLIENT, 0, SERVER, 0, bytes("hello"))));
}
