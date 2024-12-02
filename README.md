# vigenere_cipher

Cifra de Vigenere

- Como executar:
	- Para CRIPTOGRAFAR o texto:
		python script.py <nome_do_arquivo.txt> <chave> <criptografar>
		A chave de cifragem deve conter APENAS LETRAS e ter o mesmo número de caracteres que o texto, ou menos

	- Para DECRIPTOGRAFAR o texto:
		python script.py <nome_do_arquivo_cifrado.txt> <chave> <decriptografar>
		O nome do arquivo a ser decriptografado deve ser o mesmo do arquivo original, acrescido de "_cifrado"
		A chave também deve ser a mesma 




- Funcionamento do código:

	- Função "vigenere_cipher":
	Função que CIFRA ou DECIFRA o texto
	Parâmetros:
    		text: Texto lido do arquivo escolhido pelo usuário
    		key: Chave informada pelo usuário, após uso da função de derivação
    		decrypt: flag usada para escolha do que deve ser feito com o texto (CIFRAR ou DECIFRAR)
                	se VERDADEIRA, o texto será DECIFRADO
	

	- Variável 'alfabeto' recebe todo o alfabeto. Será usada para comparar, caractere a caractere, com a senha informada para cifrar/decifrar o texto. Cada letra do 		alfabeto possui um valor de 0 a 25 (sua posição na string)
	
	- 'texto_formatado': variável que recebe o texto tratado, após remoção de acentos e caracteres em lowercase

	- Cifragem: 
		Cálculo utilizado para CIFRAGEM: posição do caractere na string 'alfabeto" + posição do caractere na string da chave de cifragem
                index_caractere_cifrado é utilizado para identificar a letra cifrada, através da variável alfabeto

                Se o resultado do cálculo for MAIOR QUE 25, é aplicado o módulo de 26 (pegar o resto da divisão do valor%26). 
                O resultado será o índex do caractere cifrado

	- Decifragem:
		Cálculo utilizado para DECIFRAGEM: posição do caractere na string 'alfabeto" - posição do caractere na string da chave de decifragem
                index_caractere_cifrado é utilizado para identificar a letra cifrada, através da variável alfabeto

                Se o resultado do cálculo for MENOR QUE ZERO, é SOMADO o valor 26. 
                SE o index do caractere for MAIOR OU IGUAL A 26, é atribuído o valor ZERO(correspondente a letra A na string 'alfabeto')
                O resultado será o índex do caractere decifrado
	
	- Em ambos os casos, o texto é verificado caractere a caractere se é uma letra, caso não seja, o caractere é adicionado à string 'texto_cifrado_ou_decifrado', mantendo sua posição 	no texto lido do arquivo


                
