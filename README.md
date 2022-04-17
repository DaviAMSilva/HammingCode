# HammingCode
Uma biblioteca para codificar, decodificar, verificar e corrrigir mensagens e arquivos usando o [Código de Hamming](https://pt.wikipedia.org/wiki/C%C3%B3digo_de_Hamming)

## Principais Funções
```python
def hamming_encode(message: str, verbose: bool = False) -> str:
def hamming_decode(message: str, verbose: bool = False) -> str:
def hamming_verify(message: str, verbose: bool = False) -> tuple:
def hamming_correct(message: str, verbose: bool = False) -> str:
```

# Linha de Comando
```
usage: hamming.py [-h] [--input-mode {bits,text,binary}] [--output-mode {bits,text,binary}] [--input-file INPUT_FILE] [--output-file OUTPUT_FILE] [-v]
                  {encode,decode,verify} [message]

Hamming Encoder/Decoder

positional arguments:
  {encode,decode,verify}
                        Mode: encode, decode or verify
  message               Message to encode/decode

options:
  -h, --help            show this help message and exit
  --input-mode {bits,text,binary}
                        Input mode: bits, text, binary
  --output-mode {bits,text,binary}
                        Output mode: bits, text, binary
  --input-file INPUT_FILE
                        Input file
  --output-file OUTPUT_FILE
                        Output file
  -v, --verbose         Verbose mode
  ```
