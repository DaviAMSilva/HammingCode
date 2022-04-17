# HammingCode
Uma biblioteca para codificar, decodificar, verificar e corrigir mensagens e arquivos usando o [Código de Hamming](https://pt.wikipedia.org/wiki/C%C3%B3digo_de_Hamming)

## Principais Funções
```python
def hamming_encode(message: str, verbose: bool = False) -> str:
def hamming_decode(message: str, verbose: bool = False) -> str:
def hamming_verify(message: str, verbose: bool = False) -> tuple:
def hamming_correct(message: str, verbose: bool = False) -> str:
```

# Linha de Comando
```
usage: hamming.py [-h] [-im {bits,text,binary}] [-om {bits,text,binary}] [-if INPUT_FILE] [-of OUTPUT_FILE] [-v] {encode,decode,verify} [message]

HammingCode

positional arguments:
  {encode,decode,verify}
                        Mode: encode, decode or verify
  message               Message to encode/decode

options:
  -h, --help            show this help message and exit
  -im {bits,text,binary}, --input-mode {bits,text,binary}
                        Input mode: bits, text, binary
  -om {bits,text,binary}, --output-mode {bits,text,binary}
                        Output mode: bits, text, binary
  -if INPUT_FILE, --input-file INPUT_FILE
                        Input file
  -of OUTPUT_FILE, --output-file OUTPUT_FILE
                        Output file
  -v, --verbose         Print verbose
  ```
