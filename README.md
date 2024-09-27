# sigmaker
An experimental application for creating memory signatures of functions based on
object dumps. It only works with ```x86``` programs on ```Linux```.

> [!Warning] 
> This is experimental. If you want reliable and robust
> signatures, **do not** use this program.

# Usage

## Building
You can build ```sigmaker``` by running ```make```.

## Running
Sigmaker expects a disassembled object file (using ```objdump```) in ```intel```
syntax as its first argument. You can create the dump using the following
command:

```console
$ objdump -d -M intel <some_object.o> > <dump_name>
```

The second argument should be the name of the function for which the signature
is to be generated. You can run ```./sigmaker -h``` to see additional optional
parameters.

The generated signature will look somehting like this: ```c7 e8 ?? ?? ?? ?? 48
89 45 e0 48```. Each byte is separated by a space, without a preceding ```0x```.
The symbol ```??``` represents a wildcard for a single byte.

# Example
You can use the provided example object dump file ```example_dump.txt``` to test
the application. Execute:

```console 
$ ./sigmaker example_dump.txt example_func -l 80
```

to generate a memory signature for the ```example_func``` function that is at
most 80 bytes long.

