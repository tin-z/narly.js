# narly.js



### Description
Print binary protections using windbg JS API. in order: /SafeSEH /GS ASLR DEP NOSEH CFG_GUARD APPCONTAINER SIGNED.

The name "narly" has been borrowed from the famous windbg extension narly (https://code.google.com/archive/p/narly/).


### usage

```
!nmod ["--help"|"--info"|"--missing"|"<module-name>"]

Options:
  "--help"        : print this message
  "--info"        : print information regarding the binary protections printed out
  "--missing"     : print also binary/modules missing binary protections, instead of printing each module and its binary protections
  "<module-name>" : print module-name's binary protections

```

![1.gif](./gifs/1.gif)


