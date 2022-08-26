import re
import subprocess
import optparse

def change_mac(interface, new_mac):
    print("[+] Alterando o MAC address da interface " + interface + " para " + new_mac)

    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Alterando o MAC Address da Interface")
    parser.add_option("-m", "--mac", dest="new_mac", help="Insira o Novo MAC Address para a Interface.")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Por favor especifique a interface, use --help para mais informações.")
    if not options.new_mac:
        parser.error("[-] Por favor especifique o novo mac, use --help para mais informações.")
    return options

def get_current_mac(interface):
    ip_address_result = str(subprocess.check_output(["ip", "address", "show", interface]))
    changed = (re.search(r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', ip_address_result, flags=re.I))
    if changed:
        return changed.group(0)
    else:
        print("[-] Não foi possivel ler o MAC Address")

def view_changes(mac_atual,novo_mac):
    if mac_atual == novo_mac:
        print("[+] MAC Address alterado com sucesso para: " + mac_atual )
    else:
        print("[+] MAC Address NÃO FOI alterado para : " + novo_mac)

options = get_arguments()
current_mac = get_current_mac(options.interface)
print("MAC Address Atual: " + str(current_mac))
print("NOVO MAC Address: " + str(options.new_mac))
change_mac(options.interface, options.new_mac)
current_mac = get_current_mac(options.interface)
view_changes(current_mac,options.new_mac)


#interface = input("Por favor, insira a placa que deve ser modificada: ")
#new_mac = input("Por favor, insira o endereço do novo MAC para a placa " + interface + ": ")


#interface="wlan0"
#new_mac="00:11:22:33:44:55"