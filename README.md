# elf
Parser for ELF object format.

https://yairchu.github.io/posts/codecs-as-prisms

Symbol tables:

http://blog.k3170makan.com/2018/10/introduction-to-elf-format-part-vi.html
https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-79797.html


Special sections in Linux binaries: https://lwn.net/Articles/531148/
Understanding the ELF File Format: https://linuxhint.com/understanding_elf_file_format/
Рецепты для ELFов: https://habr.com/ru/company/inforion/blog/460247/

# Singleton

https://blog.jle.im/entry/introduction-to-singletons-1.html
https://serokell.io/blog/dimensions-haskell-singletons

# Habr Article

https://habr.com/ru/post/485174/
https://cs.stackexchange.com/questions/525/what-is-coinduction
http://homepages.inf.ed.ac.uk/slindley/papers/hasochism.pdf

# How to run tests

	cabal v2-test --test-show-details=direct

# How to update elf.nix

	cabal2nix . > ./elf.nix

# Dynamic libraries

http://www.yolinux.com/TUTORIALS/LibraryArchives-StaticAndDynamic.html
https://wiki.osdev.org/Dynamic_Linker
https://opensource.com/article/20/6/linux-libraries
https://amir.rachum.com/blog/2016/09/17/shared-libraries/
