import socket
import scapy.all as scapy
import optparse
import re
import subprocess
import pyfiglet

def print_machine_info():
    host_name = socket.gethostname()
    ip_address = socket.gethostbyname(host_name)
    print("O nome da máquina é: %s" % host_name)
    print("O endereço IP é: %s" % ip_address)


"""def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Alterando o MAC Address da Interface")
    parser.add_option("-m", "--mac", dest="new_mac", help="Insira o Novo MAC Address para a Interface.")
    (options , arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Por favor especifique a interface, use --help para mais informações.")
    if not options.new_mac:
        parser.error("[-] Por favor especifique o novo mac, use --help para mais informações.")
    return options"""


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-H", "--host", dest="host", help="Definir o IP ou DNS")
    parser.add_option("-s", "--scanHost", dest="scanhost", help="Scannear portas 0-65535", action="store_true", default=False)
    parser.add_option("-r", "--remoteHost", dest="rehost", help="Ver se está com serviços web", action="store_true", default=False)
    parser.add_option("-l", "--localhost", dest="localhost", help="Verificar localhost", action="store_true", default=False)
    parser.add_option("-i", "--infoSO", dest="sistop", help="Checar Sistema Operacional", action="store_true", default=False)
    parser.add_option("-m", "--getMAC", dest="getmac", help="Pegar MAC. Inserir IP/RANGE")
    parser.add_option("-u", "--scanUDP", dest="scanudp", help="Scan UDP das portas 0-65535", action="store_true", default=False)
    (options, args) = parser.parse_args()
    if not options.scanhost and not options.host and not options.rehost and not options.localhost and not options.sistop and not options.getmac and not options.scanudp:
        print("[*] Utilize a flag -h ou --help para mais informações.")
    return options

# Scannear portas 1-65535 - Verificar portas abertas no host - Socket
def scan_portas():
    ip = options.host
    target = socket.gethostbyname(ip)
    print("[*] IP alvo: %s" % target)
    try:
        for port in range(1, 65535):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            # returns an error indicator
            result = s.connect_ex((target, port))
            if result == 0:
                print("[*] Porta {} está aberta.".format(port))
            s.close()
    except KeyboardInterrupt:
        print("[*] Tarefa abortada, encerrando atividades.")


# Scannear portas 80 e 443
def get_remote_machine_infor():
    portas = 80, 443
    remote_host = options.host
    print("O endereço IP remoto é: %s" % socket.gethostbyname(remote_host))
    for porta in portas:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = s.connect_ex((remote_host, porta))
        if result == 0:
            print("[*] Porta {} está aberta.".format(porta))
        else:
            print("[*] Nenhuma porta 80 e/ou 443 encontrada.")
        s.close()

# Verificar localhost - Scannear portas 0-65535
def scan_localhost():
    ip = "localhost"
    target = socket.gethostbyname(ip)
    print("[*] IP localhost: %s" % target)
    try:
        for port in range(1, 65535):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            # returns an error indicator
            result = s.connect_ex((target, port))
            if result == 0:
                print("[*] Porta {} está aberta.".format(port))
            s.close()
    except KeyboardInterrupt:
        print("[*] Tarefa abortada, encerrando atividades.")


def system_check(banner2):
    linux_system_list = ["debian", "ubuntu", "linux"]
    windows_system_list = ["microsoft", "windows"]
    for os in linux_system_list:
        banner2 = str(banner2).lower()
        if os in banner2:
            return "[*] Sistema Operacional: Linux"
    for os in windows_system_list:
        banner2 = str(banner2).lower()
        if os in banner2:
            return "[*] Sistema Operacional: Windows"
    for os in linux_system_list and windows_system_list:
        if os not in banner2:
            return "Nenhum Sistema Operacional foi encontrado."


def get_system_info():
    linux_system_list = ["debian", "ubuntu", "linux"]
    windows_system_list = ["microsoft", "windows"]
    portas = 80, 443
    host = options.host
    trans = socket.gethostbyname(host)
    print("O endereço IP remoto é: %s" % trans)
    for porta in portas:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = s.connect_ex((host, porta))
        if result == 0:
            print("[*] Porta {} está aberta.".format(porta))
            banner = subprocess.check_output([f"curl -IL {trans}:{porta}"], shell=True, stderr=subprocess.DEVNULL).decode().rstrip()
            print(system_check(banner))
        else:
            print("[*] A porta %s não foi encontrada." % porta)
        s.close()


def scan_mac():
    ip = options.getmac
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_lists = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    print("IP\t\t\tMAC ADDRESS")
    for element in answered_lists:
        print(element[1].psrc + "\t\t" + element[1].hwsrc)
        print("---------------------------------------------------------------------")


def udp_scan():
    ip = options.host
    try:
        for porta in range(1,65535):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect((ip, int(porta)))
                print('[*] Porta {} aberta/filtrada.'.format(porta))
            except:
                None
            s.close()
    except KeyboardInterrupt:
        print("[*] Abortando tarefa.")


options = get_arguments()


if __name__ == '__main__':
        ascii_banner = pyfiglet.figlet_format("NINE SCAN")
        print(ascii_banner)
        if options.scanhost and options.host:
            scan_portas()
        elif options.scanhost and not options.host:
            print("[*] Insira o IP ou DNS com o '-h' ou '--host'.")

        if options.rehost and options.host:
            get_remote_machine_infor()
        elif options.rehost and not options.host:
            print("[*] Insira o IP ou DNS com o '-h' ou '--host'.")

        if options.localhost:
            scan_localhost()

        if options.sistop and options.host:
            get_system_info()
        elif options.sistop and not options.host:
            print("[*] Insira o IP ou DNS com o '-h' ou '--host'.")

        if options.getmac:
            scan_mac()

        if options.scanudp and options.host:
            udp_scan()
        elif options.scanudp and not options.host:
            print("[*] Insira o IP ou DNS com o '-h' ou '--host'.")
