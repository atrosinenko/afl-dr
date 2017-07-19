This is my experiment in dynamic instrumentation using [DynamoRIO](http://www.dynamorio.org/). It instruments target application in a way suitable for [American Fuzzy Lop](http://lcamtuf.coredump.cx/afl/) fuzzer on x86_64 GNU/Linux.

To build this project, you need CMake and working DynamoRIO installation. Use `-DDynamoRIO_DIR:STRING=/path/to/DynamoRIO-x.y.z/cmake` CMake option to specify DinamoRIO installation location.

Links:

[WinAFL](https://github.com/ivanfratric/winafl) also uses DynamoRIO for similar purpose on Windows.
