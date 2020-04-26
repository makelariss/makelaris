/* 
root@ea6685eade71:/tmp# gcc -s -DMYSQL_DYNAMIC_PLUGIN -fPIC -Wall -I/usr/include/mysql -shared -o lib_mysqludf_sys_exec64.so lib_mysqludf_sys_exec64.c
root@ea6685eade71:/tmp# file lib_mysqludf_sys_exec64.so
lib_mysqludf_sys_exec64.so: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=b5c712f0e1a0feeeb3d14d5a4cafb0156a91c2ab, stripped
*/

#include <string.h>
#include <stdlib.h>
#include <mysql.h>

my_ulonglong sys_exec(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error) {
  return system(args->args[0]);
}

my_bool sys_exec_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  if (args->arg_count == 1 && args->arg_type[0] == STRING_RESULT) {
    return 0;
  } else {
    strcpy(message, "Expected exactly one string type parameter");
    return 1;
  }
}

void sys_exec_deinit(UDF_INIT *initid);