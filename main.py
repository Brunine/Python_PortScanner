import pyfiglet
import functions

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

