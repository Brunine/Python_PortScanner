import scapy
import socket
import subprocess


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
    host = "172.20.0.10"
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




get_system_info()