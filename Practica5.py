import argparse
from time import time

import Crypto.Cipher.DES as DES
import Crypto.Cipher.DES3 as DES3
import Crypto.Random as random
import Crypto.Util.Padding as padding
import base64 as b64


def DESC(tipo, llaves, modo, archivo, contador):  # cifrado DES
    if tipo == "EEE":
        if llaves == 2:
            key1 = random.get_random_bytes(8)
            key2 = key3 = random.get_random_bytes(8)
            if modo == "CBC":
                try:
                    cipher = DES.new(key1, DES.MODE_CBC)
                    cipher2 = DES.new(key2, DES.MODE_CBC)
                    cipher3 = DES.new(key3, DES.MODE_CBC)
                    data = open(archivo, "rb")
                    plaintext = data.read()
                    msg = cipher.iv + cipher.encrypt(padding.pad(plaintext, DES.block_size))
                    msg2 = cipher2.iv + cipher2.encrypt(padding.pad(msg, DES.block_size))
                    msg3 = cipher3.iv + cipher3.encrypt(padding.pad(msg2, DES.block_size))

                    salida = open("cipher" + archivo, "wb")
                    salida.write(msg3)
                    salida.close()

                    llaves = open(archivo + ".key", "wb")
                    llaves.write(b64.standard_b64encode(key1))
                    llaves.write(b64.standard_b64encode(key2))
                    llaves.close()
                except FileNotFoundError:
                    print("El archivo especificado no pudo ser encontrado")

            elif modo == "CFB":
                try:
                    cipher = DES.new(key1, DES.MODE_CFB)
                    cipher2 = DES.new(key2, DES.MODE_CFB)
                    cipher3 = DES.new(key3, DES.MODE_CFB)
                    data = open(archivo, "rb")
                    plaintext = data.read()
                    msg = cipher.iv + cipher.encrypt(plaintext)
                    msg2 = cipher2.iv + cipher2.encrypt(msg)
                    msg3 = cipher3.iv + cipher3.encrypt(msg2)

                    salida = open("cipher" + archivo, "wb")
                    salida.write(msg3)
                    salida.close()

                    llaves = open(archivo + ".key", "wb")
                    llaves.write(b64.standard_b64encode(key1))
                    llaves.write(b64.standard_b64encode(key2))
                    llaves.close()
                except FileNotFoundError:
                    print("El archivo especificado no pudo ser encontrado")

            elif modo == "OFB":
                try:
                    cipher = DES.new(key1, DES.MODE_OFB)
                    cipher2 = DES.new(key2, DES.MODE_OFB)
                    cipher3 = DES.new(key3, DES.MODE_OFB)
                    data = open(archivo, "rb")
                    plaintext = data.read()
                    msg = cipher.iv + cipher.encrypt(plaintext)
                    msg2 = cipher2.iv + cipher2.encrypt(msg)
                    msg3 = cipher3.iv + cipher3.encrypt(msg2)

                    salida = open("cipher" + archivo, "wb")
                    salida.write(msg3)
                    salida.close()

                    llaves = open(archivo + ".key", "wb")
                    llaves.write(b64.standard_b64encode(key1))
                    llaves.write(b64.standard_b64encode(key2))
                    llaves.close()
                except FileNotFoundError:
                    print("El archivo especificado no pudo ser encontrado")

        elif llaves == 3:
            key1 = random.get_random_bytes(8)
            key2 = random.get_random_bytes(8)
            key3 = random.get_random_bytes(8)

            if modo == "CBC":
                try:
                    cipher = DES.new(key1, DES.MODE_CBC)
                    cipher2 = DES.new(key2, DES.MODE_CBC)
                    cipher3 = DES.new(key3, DES.MODE_CBC)
                    data = open(archivo, "rb")
                    plaintext = data.read()
                    msg = cipher.iv + cipher.encrypt(padding.pad(plaintext, DES.block_size))
                    msg2 = cipher2.iv + cipher2.encrypt(padding.pad(msg, DES.block_size))
                    msg3 = cipher3.iv + cipher3.encrypt(padding.pad(msg2, DES.block_size))

                    salida = open("cipher" + archivo, "wb")
                    salida.write(msg3)
                    salida.close()

                    llaves = open(archivo + ".key", "wb")
                    llaves.write(b64.standard_b64encode(key1))
                    llaves.write(b64.standard_b64encode(key2))
                    llaves.write(b64.standard_b64encode(key3))
                    llaves.close()
                except FileNotFoundError:
                    print("El archivo especificado no pudo ser encontrado")

            elif modo == "CFB":
                try:
                    cipher = DES.new(key1, DES.MODE_CFB)
                    cipher2 = DES.new(key2, DES.MODE_CFB)
                    cipher3 = DES.new(key3, DES.MODE_CFB)
                    data = open(archivo, "rb")
                    plaintext = data.read()
                    msg = cipher.iv + cipher.encrypt(plaintext)
                    msg2 = cipher2.iv + cipher2.encrypt(msg)
                    msg3 = cipher3.iv + cipher3.encrypt(msg2)

                    salida = open("cipher" + archivo, "wb")
                    salida.write(msg3)
                    salida.close()

                    llaves = open(archivo + ".key", "wb")
                    llaves.write(b64.standard_b64encode(key1))
                    llaves.write(b64.standard_b64encode(key2))
                    llaves.write(b64.standard_b64encode(key3))
                    llaves.close()
                except FileNotFoundError:
                    print("El archivo especificado no pudo ser encontrado")

            elif modo == "OFB":
                try:
                    cipher = DES.new(key1, DES.MODE_OFB)
                    cipher2 = DES.new(key2, DES.MODE_OFB)
                    cipher3 = DES.new(key3, DES.MODE_OFB)
                    data = open(archivo, "rb")
                    plaintext = data.read()
                    msg = cipher.iv + cipher.encrypt(plaintext)
                    msg2 = cipher2.iv + cipher2.encrypt(msg)
                    msg3 = cipher3.iv + cipher3.encrypt(msg2)

                    salida = open("cipher" + archivo, "wb")
                    salida.write(msg3)
                    salida.close()

                    llaves = open(archivo + ".key", "wb")
                    llaves.write(b64.standard_b64encode(key1))
                    llaves.write(b64.standard_b64encode(key2))
                    llaves.write(b64.standard_b64encode(key3))
                    llaves.close()
                except FileNotFoundError:
                    print("El archivo especificado no pudo ser encontrado")
        else:
            print("Numero de llaves no valido")

#uso de la libreria
    elif tipo == "EDE":
        if llaves == 2:
            key = random.get_random_bytes(16)
            if modo == "CBC":
                try:
                    file = open(archivo, "rb")
                    plaintext = file.read()
                    cipher = DES3.new(key, DES3.MODE_CBC)
                    cipherText = cipher.iv + cipher.encrypt(padding.pad(plaintext, DES3.block_size))
                    salida = open("cipher" + archivo, "wb")
                    salida.write(cipherText)
                    salida.close()
                    llaves = open(archivo + ".key", "w")
                    llaves.write(b64.standard_b64encode(key))
                    llaves.close()
                except FileNotFoundError:
                    print("El archivo especificado no pudo ser encontrado")

            elif modo == "CFB":
                try:
                    file = open(archivo, "rb")
                    plaintext = file.read()
                    cipher = DES3.new(key, DES3.MODE_CFB)
                    cipherText = cipher.iv + cipher.encrypt(plaintext)
                    salida = open("cipher" + archivo, "wb")
                    salida.write(cipherText)
                    salida.close()
                    llaves = open(archivo + ".key", "w")
                    llaves.write(b64.standard_b64encode(key))
                    llaves.close()
                except FileNotFoundError:
                    print("El archivo especificado no pudo ser encontrado")

            elif modo == "OFB":
                try:
                    file = open(archivo, "rb")
                    plaintext = file.read()
                    cipher = DES3.new(key, DES3.MODE_OFB)
                    cipherText = cipher.iv + cipher.encrypt(plaintext)
                    salida = open("cipher" + archivo, "wb")
                    salida.write(cipherText)
                    salida.close()
                    llaves = open(archivo + ".key", "w")
                    llaves.write(b64.standard_b64encode(key))
                    llaves.close()
                except FileNotFoundError:
                    print("El archivo especificado no pudo ser encontrado")
        elif llaves == 3:
            key = random.get_random_bytes(24)

            if modo == "CBC":
                try:
                    file = open(archivo, "rb")
                    plaintext = file.read()
                    cipher = DES3.new(key, DES3.MODE_CBC)
                    cipherText = cipher.iv + cipher.encrypt(padding.pad(plaintext, DES3.block_size))
                    salida = open("cipher" + archivo, "wb")
                    salida.write(cipherText)
                    salida.close()
                    llaves = open(archivo + ".key", "w")
                    llaves.write(b64.standard_b64encode(key))
                    llaves.close()
                except FileNotFoundError:
                    print("El archivo especificado no pudo ser encontrado")

            elif modo == "CFB":
                try:
                    file = open(archivo, "rb")
                    plaintext = file.read()
                    cipher = DES3.new(key, DES3.MODE_CFB)
                    cipherText = cipher.iv + cipher.encrypt(plaintext)
                    salida = open("cipher" + archivo, "wb")
                    salida.write(cipherText)
                    salida.close()
                    llaves = open(archivo + ".key", "w")
                    llaves.write(b64.standard_b64encode(key))
                    llaves.close()
                except FileNotFoundError:
                    print("El archivo especificado no pudo ser encontrado")

            elif modo == "OFB":
                try:
                    file = open(archivo, "rb")
                    plaintext = file.read()
                    cipher = DES3.new(key, DES3.MODE_OFB)
                    cipherText = cipher.iv + cipher.encrypt(plaintext)
                    salida = open("cipher" + archivo, "wb")
                    salida.write(cipherText)
                    salida.close()
                    llaves = open(archivo + ".key", "w")
                    llaves.write(b64.standard_b64encode(key))
                    llaves.close()
                except FileNotFoundError:
                    print("El archivo especificado no pudo ser encontrado")
        else:
            print("Numero de llaves no valido")
    else:
        print("Opción no valida")

def DESD(tipo, llaves, modo, archivo, contador):  # Descifrado DES
    if tipo == "EEE":
        if modo == "CBC":
            data = open(llaves, "rb")
            data = data.read()
            if len(data) == 24:
                key1 = b64.standard_b64decode(data[0:12])
                key2 = key3 = b64.standard_b64decode(data[12:24])

            elif len(data) == 36:
                key1 = b64.standard_b64decode(data[0:12])
                key2 = b64.standard_b64decode(data[12:24])
                key3 = b64.standard_b64decode(data[24:36])
            file = open("cipher" + archivo, "rb")
            ciphertext = file.read()
            iv = ciphertext[:DES.block_size]
            cipher = DES.new(key3, DES.MODE_CBC, iv)
            msg = padding.unpad(cipher.decrypt(ciphertext[DES.block_size:]), DES.block_size)

            iv2 = msg[:DES.block_size]
            cipher2 = DES.new(key2, DES.MODE_CBC, iv2)
            msg2 =padding.unpad(cipher2.decrypt(msg[DES.block_size:]), DES.block_size)

            iv3 = msg2[:DES.block_size]
            cipher3 = DES.new(key1, DES.MODE_CBC, iv3)
            msg3 = padding.unpad(cipher3.decrypt(msg2[DES.block_size:]), DES.block_size)


            salida = open("D" + archivo, "wb")
            salida.write(msg3)

        elif modo == "CFB":
            data = open(llaves, "rb")
            data = data.read()
            if len(data) == 24:
                key1 = b64.standard_b64decode(data[0:12])
                key2 = key3 = b64.standard_b64decode(data[12:24])

            elif len(data) == 36:
                key1 = b64.standard_b64decode(data[0:12])
                key2 = b64.standard_b64decode(data[12:24])
                key3 = b64.standard_b64decode(data[24:36])
            data = open("cipher" + archivo, "rb")
            ciphertext = data.read()
            iv = ciphertext[:DES.block_size]
            cipher = DES.new(key3, DES.MODE_CFB, iv)
            msg = cipher.decrypt(ciphertext[DES.block_size:])


            iv2 = msg[:DES.block_size]
            cipher2 = DES.new(key2, DES.MODE_CFB, iv2)
            msg2 = cipher2.decrypt(msg[DES.block_size:])


            iv3 = msg2[:DES.block_size]
            cipher3 = DES.new(key1, DES.MODE_CFB, iv3)
            msg3 = cipher3.decrypt(msg2[DES.block_size:])
            salida = open("D" + archivo, "wb")
            salida.write(msg3)
        elif modo == "OFB":
            try:
                data = open(llaves, "rb")
                data = data.read()
                if len(data) == 24:
                    key1 = b64.standard_b64decode(data[0:12])
                    key2 = key3 = b64.standard_b64decode(data[12:24])

                elif len(data) == 36:
                    key1 = b64.standard_b64decode(data[0:12])
                    key2 = b64.standard_b64decode(data[12:24])
                    key3 = b64.standard_b64decode(data[24:36])
                data = open("cipher" + archivo, "rb")
                ciphertext = data.read()
                iv = ciphertext[:DES.block_size]
                cipher = DES.new(key3, DES.MODE_OFB, iv)
                msg = cipher.decrypt(ciphertext[DES.block_size:])

                iv2 = msg[:DES.block_size]
                cipher2 = DES.new(key2, DES.MODE_OFB, iv2)
                msg2 = cipher2.decrypt(msg[DES.block_size:])

                iv3 = msg2[:DES.block_size]
                cipher3 = DES.new(key1, DES.MODE_OFB, iv3)
                msg3 = cipher3.decrypt(msg2[DES.block_size:])

                salida = open("D" + archivo, "wb")
                salida.write(msg3)

            except FileNotFoundError:
             print("El archivo especificado no pudo ser encontrado")
        else:
            print("Llave no valida")
    # Uso de la criptolibreria
    elif tipo == "EDE":
        if modo == "CBC":
            data = open("cipher" + archivo, "rb")
            data2 = open(llaves, "rb")
            plaintext = data.read()
            key = b64.standard_b64decode(data2.read())
            iv = plaintext[:DES3.block_size]
            cipher = DES3.new(key, DES3.MODE_OFB, iv)
            msg = cipher.decrypt(plaintext[DES3.block_size:])
            msg = padding.unpad(msg,DES3.block_size)
            salida = open("D" + archivo, "wb")
            salida.write(msg)
            salida.close()
        elif modo == "CFB":
            data = open("cipher" + archivo, "rb")
            data2 = open(llaves, "rb")
            plaintext = data.read()
            key = b64.standard_b64decode(data2.read())
            iv = plaintext[:DES3.block_size]
            cipher = DES3.new(key, DES3.MODE_CFB, iv)
            msg = cipher.decrypt(plaintext[DES3.block_size:])
            salida = open("D" + archivo, "wb")
            salida.write(msg)
            salida.close()
        elif modo == "OFB":
            data = open("cipher" + archivo, "rb")
            data2 = open(llaves, "rb")
            plaintext = data.read()
            key = b64.standard_b64decode(data2.read())
            iv = plaintext[:DES3.block_size]
            cipher = DES3.new(key, DES3.MODE_OFB, iv)
            msg = cipher.decrypt(plaintext[DES3.block_size:])
            salida = open("D" + archivo, "wb")
            salida.write(msg)
            salida.close()
        else:
            print("Llave no valida")
    else:
        print("Opción no valida")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--cifrar", help="Cifra el archivo y devuelve la llave con el archivo cifrado",
                        action="store_true")
    parser.add_argument("-d", "--descifrar", help="Descifra el archivo seleccionado",
                        action="store_true")
    parser.add_argument("-t", "--tipo", help="Tipo de configuracion DES:  EEE | EDE ", default="EEE")
    parser.add_argument("-m", "--modo", help="Modo de operacion CBC | CTR | OFB | CFB ", default="OFB")
    parser.add_argument("-f", "--file", help="Nombre del archivo")
    parser.add_argument("-kn", "--keynumber", help="Numero de llaves que se usaran MAX 3", type=int, default=3)
    parser.add_argument("-cn", "--contador", help="Valor inicial del contador", type=int, default=2)
    parser.add_argument("-k", "--key", help="Nombre del archivo con las llaves")
    args = parser.parse_args()

    tiempoInicial = time()
    DESC(args.tipo, args.keynumber, args.modo, args.file, args.contador)
    tiempoFinal =time()
    tiempoEjecucionCifrado =tiempoFinal - tiempoInicial

    tiempoInicialD = time()
    DESD(args.tipo, args.key, args.modo, args.file, args.contador)
    tiempoFinalD = time()
    tiempoEjecucionDescifrado = tiempoFinalD - tiempoInicialD
    print("Tiempo ejecucion Cifrado",tiempoEjecucionCifrado)
    print("Tiempo ejecucion Descifrado",tiempoEjecucionDescifrado)


if __name__ == "__main__":
    main()
