# IDA Batch Decompilation Script
IDA supports terminal-based batch decompilation:  
https://hex-rays.com/products/decompiler/manual/batch.shtml  
It's a powerful feature but it's not very configurable and is missing 2 types of data which I find important:  
1. No dump of all string. (Only strings used in subroutine bodies are embedded)
2. No exports

For that reason I wrote this 3-parts python script which dumps the other parts and 
combines the results into a single .c file.

## Usage
Run:  
`python.exe batch_decompile.py <YOUR_INPUT_FILE_PATH>`  
NOTE: Tested with python 10 & IDA 7.0  
For other versions of ida, change the path to "ida64.exe" in `batch_decompile.py`  

Results will be 2 intermediate .c files and the final dump, called:  
```*YOUR_INPUT_FILE_NAME*_final_decomp.c```
