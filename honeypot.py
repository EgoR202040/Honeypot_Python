import socket
import threading
import time
import json
import logging
import argparse
from datetime import datetime
from collections import defaultdict
import ipaddress
import struct
import select
import os
import sys
from typing import Dict, List, Tuple, Optional

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('honeypot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class HoneypotConfig:
    def __init__(self):
        self.ports = [22, 80, 443, 2222, 8080, 8443]
        self.host = '0.0.0.0'
        self.max_connections = 100 
        self.timeout = 30  # Таймаут соединения в секундах
        self.scan_threshold = 10 
        self.banner = {
            22: b'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n',
            80: b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n',
            443: b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n',
            2222: b'SSH-2.0-OpenSSH_7.4\r\n',
            8080: b'HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n',
            8443: b'HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n'
        }
        self.log_file = 'honeypot_audit.log'
        self.alert_on_scan = True

class ConnectionTracker:
    def __init__(self, scan_threshold: int = 10):
        self.connections = defaultdict(list)
        self.scan_threshold = scan_threshold
        self.scan_detected = defaultdict(bool)
        self.lock = threading.Lock()
        
    def add_connection(self, ip: str, port: int): #Добавление соединения в трекер соединений
        timestamp = time.time()
        with self.lock:
            self.connections[ip].append((timestamp, port))
            cutoff = timestamp - 60
            self.connections[ip] = [
                (ts, p) for ts, p in self.connections[ip] if ts > cutoff
            ]
            
            if self._detect_scan(ip):
                self.scan_detected[ip] = True
                return True
        return False
    
    def _detect_scan(self, ip: str) -> bool:
        connections = self.connections[ip]
        if len(connections) < self.scan_threshold:
            return False
       
        connections.sort(key=lambda x: x[0]) #Сортировка с помощью лямбда-функции

        unique_ports = set(port for _, port in connections)
        if len(unique_ports) >= 5:
            time_diff = connections[-1][0] - connections[0][0]
            if time_diff < 10: 
                return True
        
        recent_time = time.time() - 5
        recent_connections = [ts for ts, _ in connections if ts > recent_time]
        if len(recent_connections) >= self.scan_threshold:
            return True
            
        return False
    
    def get_stats(self, ip: str) -> Dict:
        with self.lock:
            conns = self.connections.get(ip, [])
            ports = [port for _, port in conns]
            return {
                'total_connections': len(conns),
                'unique_ports': len(set(ports)),
                'ports_scanned': sorted(set(ports)),
                'scan_detected': self.scan_detected.get(ip, False),
                'last_activity': max([ts for ts, _ in conns]) if conns else None
            }

class ServiceEmulator:
    @staticmethod
    def emulate_ssh(client_socket: socket.socket, client_ip: str):
        try:
            client_socket.send(b'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n') #SSH баннер
            
            data = client_socket.recv(1024)
            if data:
                logger.info(f"SSH client banner from {client_ip}: {data[:100]}")
            
            client_socket.send(b'Protocol mismatch.\r\n')
            
        except Exception as e:
            logger.debug(f"SSH emulation error for {client_ip}: {e}")
        finally:
            client_socket.close()
    
    @staticmethod
    def emulate_http(client_socket: socket.socket, client_ip: str):
        try:
            request = client_socket.recv(4096).decode('utf-8', errors='ignore')
            if request:
                logger.info(f"HTTP request from {client_ip}:\n{request[:500]}")
            
            # Формируем HTTP ответ
            response = """HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Connection: close

<!DOCTYPE html>
<html>
<head><title>Welcome</title></head>
<body>
<h1>Welcome to our server!</h1>
<p>This is a default page.</p>
</body>
</html>"""
            
            client_socket.send(response.encode())
            
        except Exception as e:
            logger.debug(f"HTTP emulation error for {client_ip}: {e}")
        finally:
            client_socket.close()
    
    @staticmethod
    def emulate_telnet(client_socket: socket.socket, client_ip: str):
        try:
            client_socket.send(b'\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f')
            client_socket.send(b'\r\nWelcome to Service\r\n\r\nlogin: ')
            
            data = client_socket.recv(1024)
            if data:
                logger.info(f"Telnet attempt from {client_ip}: {data[:100]}")
            
            client_socket.send(b'\r\nPassword: ')
            time.sleep(1)
            client_socket.send(b'\r\nLogin incorrect\r\n')
            
        except Exception as e:
            logger.debug(f"Telnet emulation error for {client_ip}: {e}")
        finally:
            client_socket.close()

class HoneypotServer:
    def __init__(self, config: HoneypotConfig):
        self.config = config
        self.tracker = ConnectionTracker(config.scan_threshold)
        self.emulator = ServiceEmulator()
        self.running = False
        self.servers = []
        
    def start(self):
        self.running = True
        logger.info(f"Starting honeypot on ports: {self.config.ports}")

        for port in self.config.ports:
            server_thread = threading.Thread(
                target=self._start_server,
                args=(port,),
                daemon=True
            )
            server_thread.start()
            self.servers.append(server_thread)
        
        monitor_thread = threading.Thread(target=self._monitor_activity, daemon=True)
        monitor_thread.start()
        
        logger.info("Honeypot is running. Press Ctrl+C to stop.")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def _start_server(self, port: int):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.settimeout(5)
            
            server_socket.bind((self.config.host, port))
            server_socket.listen(self.config.max_connections)
            
            logger.info(f"Listening on port {port}")
            
            while self.running:
                try:
                    client_socket, client_address = server_socket.accept()
                    client_socket.settimeout(self.config.timeout)

                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address, port),
                        daemon=True
                    )
                    client_thread.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error accepting connection on port {port}: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to start server on port {port}: {e}")
    
    def _handle_client(self, client_socket: socket.socket, 
                      client_address: Tuple[str, int], port: int):
        client_ip = client_address[0]
        
        try:
            logger.info(f"New connection from {client_ip}:{client_address[1]} to port {port}")
            
            is_scan = self.tracker.add_connection(client_ip, port)
            
            if is_scan and self.config.alert_on_scan:
                self._alert_scan(client_ip, port)

            self._emulate_service(client_socket, client_ip, port)

            self._log_connection(client_ip, client_address[1], port, is_scan)
            
        except Exception as e:
            logger.error(f"Error handling client {client_ip}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _emulate_service(self, client_socket: socket.socket, 
                        client_ip: str, port: int):
        try:
            if port in self.config.banner:
                client_socket.send(self.config.banner[port]) #Отправка баннера если есть
            if port in [22, 2222, 22222]:
                self.emulator.emulate_ssh(client_socket, client_ip)
            elif port in [80, 8080, 8000]:
                self.emulator.emulate_http(client_socket, client_ip)
            elif port == 23:
                self.emulator.emulate_telnet(client_socket, client_ip)
            elif port in [443, 8443]:
                time.sleep(0.5)
            else:
                time.sleep(1)
                
        except Exception as e:
            logger.debug(f"Service emulation error for {client_ip}:{port}: {e}")
    
    def _alert_scan(self, ip: str, port: int):
        stats = self.tracker.get_stats(ip)
        alert_msg = (
            f"⚠️  SCAN DETECTED ⚠️\n"
            f"Source IP: {ip}\n"
            f"Target Port: {port}\n"
            f"Total Connections: {stats['total_connections']}\n"
            f"Unique Ports: {stats['unique_ports']}\n"
            f"Ports Scanned: {stats['ports_scanned']}\n"
            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        
        logger.warning(alert_msg)
        
        with open('scan_alerts.log', 'a') as f:
            f.write(f"{datetime.now().isoformat()} - {alert_msg}\n")
    
    def _log_connection(self, ip: str, src_port: int, 
                       dst_port: int, is_scan: bool):
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': ip,
            'source_port': src_port,
            'destination_port': dst_port,
            'is_scan': is_scan,
            'geolocation': self._get_geolocation(ip)
        }
        
        with open(self.config.log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def _get_geolocation(self, ip: str) -> str: #Попытка определения типа сети из которой сделано сканирование
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return "Private Network"
            elif ip_obj.is_loopback:
                return "Localhost"
            else:
                return "Public IP"
        except:
            return "Unknown"
    
    def _monitor_activity(self):
        while self.running:
            time.sleep(60

            all_ips = list(self.tracker.connections.keys())
            if not all_ips:
                continue
            
            logger.info("=" * 50)
            logger.info("Activity Report")
            logger.info("=" * 50)
            
            for ip in all_ips[:10]:
                stats = self.tracker.get_stats(ip)
                if stats['total_connections'] > 0:
                    logger.info(
                        f"IP: {ip} - "
                        f"Connections: {stats['total_connections']} - "
                        f"Unique ports: {stats['unique_ports']} - "
                        f"Scan detected: {stats['scan_detected']}"
                    )
            
            logger.info("=" * 50)
    
    def stop(self):
        self.running = False
        logger.info("Stopping honeypot...")
        time.sleep(2)

def parse_arguments():
    parser = argparse.ArgumentParser(description='Honeypot для обнаружения сетевых сканирований')
    
    parser.add_argument('--ports', type=str, default='22,80,443,2222,8080',
                       help='Порты для прослушивания (через запятую)')
    parser.add_argument('--host', type=str, default='0.0.0.0',
                       help='IP адрес для прослушивания')
    parser.add_argument('--threshold', type=int, default=10,
                       help='Порог обнаружения сканирования (подключений/сек)')
    parser.add_argument('--log-file', type=str, default='honeypot.log',
                       help='Файл для логов')
    parser.add_argument('--no-alert', action='store_true',
                       help='Отключить предупреждения о сканировании')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Подробный вывод')
    
    return parser.parse_args()

def main():
    args = parse_arguments()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        ports = [int(p.strip()) for p in args.ports.split(',')]
    except ValueError:
        logger.error("Неверный формат портов. Используйте: 22,80,443") #Стандартные порты
        return
    
    if any(p < 1024 for p in ports) and os.geteuid() != 0:
        logger.warning("Для прослушивания портов ниже 1024 требуются права root")
        logger.warning("Запустите: sudo python honeypot.py")
        ports = [p for p in ports if p >= 1024]
        if not ports:
            ports = [2222, 8080, 8443]
    
    config = HoneypotConfig()
    config.ports = ports
    config.host = args.host
    config.scan_threshold = args.threshold
    config.log_file = args.log_file
    config.alert_on_scan = not args.no_alert

    honeypot = HoneypotServer(config)
    
    try:
        honeypot.start()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
    finally:
        honeypot.stop()

if __name__ == "__main__":
    main()
