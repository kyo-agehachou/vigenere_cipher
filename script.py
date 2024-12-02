#@Author: Kellen E. S. Jhanke

import unicodedata # módulo com funções para trabalhar com caracteres e strings em Unicode.Usado para normalização de texto (remover acentos)
import os  # Para lidar com caminhos e manipulação de arquivos
import sys  # Para capturar argumentos de linha de comando
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # Para derivar uma chave segura
from cryptography.hazmat.primitives import hashes # Algoritmo de hash (SHA-256)
import base64  # Para codificar e decodificar em base64

def derive_key(password) -> str:
    """
    Deriva uma chave baseada na senha e no salt usando PBKDF2.
    password: Senha fornecida pelo usuário.
    salt: Valor aleatório usado para fortalecer a derivação da chave.
    Retorna: Uma chave em formato string.
    """
    # Configura o algoritmo PBKDF2 para gerar a chave
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Algoritmo de hash SHA-256
        length=32,  # Comprimento da chave derivada       
        salt=password.encode(encoding='utf-8'), # Salt usado para proteção contra ataques de dicionário
        iterations=100000,  # Número de iterações (aumenta a segurança)
    )
    
    # 1. Converte a senha (string) para bytes
    password_bytes = password.encode(encoding='utf-8')

    # 2. Usa o método derive do KDF (Key Derivation Function) para gerar a chave bruta em bytes
    raw_key = kdf.derive(password_bytes)   

    # 3. Codifica a chave bruta em Base64 URL-safe para torná-la legível
    encoded_key = base64.urlsafe_b64encode(raw_key)

    # 4. Decodifica o Base64 (bytes) para uma string utilizável
    derived_key = encoded_key.decode()
    
    return derived_key



def normalizar_texto(texto: str) -> str:
    """
    Remove acentos de letras em uma string
    texto: String de entrada.
    Retorna: String sem acentos e com caracteres em minúsculo
    """
    # Normaliza a string para o formato NFD (decomposição Unicode)
    texto_normalizado = unicodedata.normalize('NFD', texto)

    # Filtra apenas os caracteres
    texto_sem_acentos = ''.join(
        char for char in texto_normalizado if not unicodedata.combining(char)
    )

    return texto_sem_acentos.lower()


def tratar_senha(key) -> str:
    """
    Cifra de Vegenere utiliza apenas letras, é preciso remover número e caracteres especiais contidos na senha ao utilizar a derivação (PBKDF2)    
    key: String gerada a partir da função derive_key()
    Retorna: String apenas com letras
    """

    senha_tratada = ''

    for caractere in key:
        if caractere.isalpha():
            senha_tratada = senha_tratada + caractere
    return senha_tratada


#Cifra de Vigenere
def vigenere_cipher(text, key, decrypt) -> str:

    """
    Função que CIFRA ou DECIFRA o texto
    text: Texto lido do arquivo escolhido pelo usuário
    key: Chave informada pelo usuário, após uso da função de derivação
    decrypt: flag usada para escolha do que deve ser feito com o texto (CIFRAR ou DECIFRAR)
            se VERDADEIRA, o texto será DECIFRADO
    """

    """
    Variável 'alfabeto' recebe alfabeto que será usado para comparar, caractere a caractere, com a senha informada para cifrar/decifrar texto
    Cada letra do alfabeto possui um valor de 0 a 25 (sua posição na string)
    """
    alfabeto = 'abcdefghijklmnopqrstuvwxyz' 
    texto_formatado = normalizar_texto(text) # Uso da função para remover acentos do texto e passar todos os caracteres para minúsculo

    i = 0 #inicialização do index usado para percorrer a string da chave
    
    texto_cifrado_ou_decifrado = '' #Variável que receberá os caracteres cifrados/decifrados  

    key = key.lower()
    key = tratar_senha(key) # Uso da função para remover todos os caracteres da chave derivada que não sejam letras
    key_length = len(key)
 

    if (not decrypt): #Se escolher CRIPTOGRAFAR o texto
        
        for caractere in texto_formatado:
            if caractere.isalpha(): #verifica se o caractere do texto é uma letra       

                """
                    Cálculo utilizado para CIFRAGEM: posição do caractere na string 'alfabeto" + posição do caractere na string da chave de cifragem
                    index_caractere_cifrado é utilizado para identificar a letra cifrada, através da variável alfabeto

                    Se o resultado do cálculo for MAIOR QUE 25, é aplicado o módulo de 26 (pegar o resto da divisão do valor%26). 
                    O resultado será o índex do caractere cifrado
                """

                if ((alfabeto.find(caractere) + alfabeto.find((key[i]))) <= 25):
                    index_caractere_cifrado = alfabeto.find(caractere) + alfabeto.find((key[i]))

                else:
                    index_caractere_cifrado = (alfabeto.find(caractere) + (alfabeto.find(((key[i]))))) % 26

                # Concatena o caractere cifrado ao texto  
                texto_cifrado_ou_decifrado = texto_cifrado_ou_decifrado + (alfabeto[index_caractere_cifrado])

                """
                    Itera o index da CHAVE (apenas se o caractere do TEXTO for uma letra)
                    Zera o index para percorrer a senha novamente toda vez que tiver completado a iteração
                    A senha pode ser percorrida várias vezes, até que o TEXTO tenha sido totalmente processado
                """
                if (i < (key_length - 1)):
                    i = i+1
                else:
                    i = 0                

            else: 
                #Se o caractere do texto NÃO for uma letra, apenas é adicionado à string na mesma posição do texto original
                texto_cifrado_ou_decifrado = texto_cifrado_ou_decifrado + caractere

            print("TEXTO CIFRADO", texto_cifrado_ou_decifrado)


    if (decrypt): #Se escolher DECRIPTOGRAFAR o texto
        
        for caractere in texto_formatado:
            if caractere.isalpha():              

                """
                    Cálculo utilizado para DECIFRAGEM: posição do caractere na string 'alfabeto" - posição do caractere na string da chave de decifragem
                    index_caractere_cifrado é utilizado para identificar a letra cifrada, através da variável alfabeto

                    Se o resultado do cálculo for MENOR QUE ZERO, é SOMADO o valor 26. 
                    Se o index do caractere for MAIOR OU IGUAL A 26, é atribuído o valor ZERO(correspondente a letra A na string 'alfabeto')
                    O resultado será o índex do caractere decifrado
                """

                if ((alfabeto.find(caractere) - alfabeto.find((key[i]))) >= 0 ):
                    index_caractere_cifrado = alfabeto.find(caractere) - alfabeto.find((key[i]))   
                else:
                    index_caractere_cifrado = (alfabeto.find(caractere) - (alfabeto.find(((key[i]))))) + 26
                  
                    if(index_caractere_cifrado >= 26):
                        index_caractere_cifrado = 0
                   
                # Concatena o caractere decifrado ao texto 
                texto_cifrado_ou_decifrado = texto_cifrado_ou_decifrado + (alfabeto[index_caractere_cifrado])

                """
                    Itera o index da CHAVE (apenas se o caractere do TEXTO for uma letra)
                    Zera o index para percorrer a senha novamente toda vez que tiver completado a iteração
                    A senha pode ser percorrida várias vezes, até que o TEXTO tenha sido totalmente processado
                """
                if (i < (key_length - 1)):
                    i = i+1
                else:
                    i = 0
                
            else:
                #Se o caractere do texto NÃO for uma letra, apenas é adicionado à string na mesma posição do texto original
                texto_cifrado_ou_decifrado = texto_cifrado_ou_decifrado + caractere

            print("TEXTO DECIFRADO", texto_cifrado_ou_decifrado)

    return texto_cifrado_ou_decifrado  #Retorna o texto depois de cifrado ou decifrado


def process_file(input_file: str, password: str, cifra_ou_decifra: str):
    """
    Processa o arquivo para cifrar ou decifrar.
    input_file: Nome do arquivo de entrada.
    password: Senha para derivar a chave.
    cifra_ou_decifra: Indica se deve 'criptografar' ou 'decriptografar'.
    """
    if not os.path.exists(input_file):  # Verifica se o arquivo existe
        print(f"Erro: Arquivo '{input_file}' não encontrado.")
        sys.exit(1)

    # Define nomes de saída para os arquivos
    if cifra_ou_decifra == "criptografar":
        # Se escolhido CRIPTOGRAFAR, gera um arquivo txt com nome baseado no arquivo original,porém identificando que foi crifrado
        output_file = input_file.replace('.txt', '_cifrado.txt')
    elif cifra_ou_decifra == "decriptografar":
        # Se escolhido DECRIPTOGRAFAR, gera um arquivo txt com nome baseado no arquivo CIFRADO,porém identificando que foi decrifrado
        output_file = input_file.replace('_cifrado.txt', '_decifrado.txt')
    else:
        print("Erro: O modo deve ser 'criptografar' ou 'decriptografar'.")
        sys.exit(1)


    key = derive_key(password) #uso da função de derivação
    

    with open(input_file, 'r', encoding='utf-8') as f:  # Abre o arquivo para leitura
        text = f.read()  # Lê o conteúdo do arquivo
    
    if ( len(password) > len(text) ):  # Verifica se a senha possui mais caracteres que o texto lido do arquivo
        print("O tamanho da CHAVE deve ser MENOR ou IGUAL ao tamanho do texto")
        sys.exit(1)
    
    # Cifra ou decifra o texto
    if cifra_ou_decifra == "criptografar":
        processed_text = vigenere_cipher(
            text, key, decrypt = False)  # Criptografa o texto
    else:
        processed_text = vigenere_cipher(
            text, key, decrypt = True)  # Decriptografa o texto

    # Escreve o texto processado no arquivo de saída
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(processed_text)

    print(f"Arquivo processado com sucesso: {output_file}")


# ================================= INÍCIO DA EXECUÇÃO =================================
# Captura os argumentos da linha de comando
if len(sys.argv) != 4:
    print("Uso: python script.py <arquivo.txt> <chave> <criptografar ou decriptografar>")
    sys.exit(1)

input_file = sys.argv[1]  # Nome do arquivo de entrada
password = sys.argv[2]  # Chave de cifragem
cifra_ou_decifra = sys.argv[3].lower()  # Modo: 'criptografar' ou 'decriptografar'

if (password.isalpha()):  # Verifica se a senha é composta apenas por letras
    process_file(input_file, password, cifra_ou_decifra)  # Executa o processamento
else:
    print("A chave de criptografia deve conter APENAS LETRAS")
    sys.exit(1)