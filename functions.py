import socket
import scapy
import optparse
import re

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
    parser.add_option("-H", "--host", dest="host", help="Definir o IP")
    parser.add_option("-s", "--scanHost", dest="scanhost", help="Scannear portas 0-65535")
    parser.add_option("-r", "--remoteHost", dest="rehost", help="Ver se está com serviços web")
    (options, arguments) = parser.parse_args()
    if not options.scanhost and not options.host and not options.rehost:
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
    remote_host = options.rehost
    print("O endereço IP remoto é: %s" % socket.gethostbyname(remote_host))
    for porta in portas:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = s.connect_ex((remote_host, porta))
        if result == 0:
            print("[*] Porta {} está aberta.".format(porta))
        s.close()

options = get_arguments()

if options.rehost:
    get_remote_machine_infor()
