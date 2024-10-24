#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openssl/sha.h>

    uint8_t hex_to_byte(unsigned char h1, unsigned char h2){
        uint8_t value1, value2;
        if(h1>='0' && h1<='9'){ //first char
            value1 = h1 - '0';
       }
       else if(h1>='a' && h1<='f'){
        value1 = h1 - 'a' + 10;
       }
       else if(h1>='A' && h1<='F'){
        value1 = h1 - 'A' +10;
       }
       else {
        return 0;
       }
       if(h2>='0' && h2<='9'){ //second cahrnn
        value2 = h2 - '0';
       }
       else if(h2>='a' && h2<='f'){
        value2 = h2 - 'a' + 10;
       }
       else if(h2>='A' && h2<='F'){
        value2 = h2 - 'A' + 10;
       }
       else{
        return 0;
       }
       return (value1 << 4) | value2;
}
    void hexstr_to_hash(char hexstr[], unsigned char hash[32]){
        for(int i = 0; i<32; i++){
            hash[i] = hex_to_byte(hexstr[2*i], hexstr[2 * i + 1]);
        }
}
    int8_t check_password(char password[], unsigned char given_hash[32]) {
        unsigned char hash[32];    
        SHA256((unsigned char*)password, strlen(password), hash);
        return (memcmp(hash, given_hash, 32) == 0) ? 1 : 0;
}
    int8_t crack_password(char password[], unsigned char given_hash[32]) {
            if (check_password(password, given_hash)) {
                return 1;
}
        for (size_t i = 0; i < strlen(password); i++) {
            if (!isalpha(password[i])) continue;
                char original_char = password[i];
            if (islower(password[i])) {
                password[i] = toupper(password[i]);
            } else {
                password[i] = tolower(password[i]);
            }
            if (check_password(password, given_hash)) {
                return 1;
        }
        password[i] = original_char;
    }
    return 0; 
}
    void test_check_password() {
        char hash_as_hexstr[] = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"; 
        unsigned char given_hash[32];
        hexstr_to_hash(hash_as_hexstr, given_hash);
        assert(check_password("password", given_hash) == 1);
        assert(check_password("notpassword", given_hash) == 0);
      //  printf("test_check_password passed.\n");
}
    void test_hex_to_byte() {
        assert(hex_to_byte('c', '8') == 200);
        assert(hex_to_byte('0', '3') == 3);
        assert(hex_to_byte('0', 'a') == 10);
        assert(hex_to_byte('1', '0') == 16);
        assert(hex_to_byte('f', 'f') == 255);
      //  printf("test_hex_to_byte passed.\n");
}
    void test_hexstr_to_hash() {
        char hexstr[64] = "a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd";
        unsigned char hash[32];
        hexstr_to_hash(hexstr, hash);
        printf("Result of hexstr_to_hash:\n");
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
        if (i < 31) printf(" ");
    }
        printf("\n");
        assert(hash[0] == 0xa2);
        assert(hash[1] == 0xc3);
        assert(hash[30] == 0x4f);
        assert(hash[31] == 0xfd);
     //   printf("test_hexstr_to_hash passed.\n");
}
    void test_crack_password() {
        char hash_as_hexstr[] = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"; 
        unsigned char given_hash[32];
        hexstr_to_hash(hash_as_hexstr, given_hash);
        char password[] = "paSsword";
        assert(crack_password(password, given_hash) == 1);
        assert(password[2] == 's'); 
        char wrong_password[] = "wrongpass";
        assert(crack_password(wrong_password, given_hash) == 0);
       // printf("test_crack_password passed.\n"); 
}
    int main(int argc, char** argv){
        const int testing = 0;
    if (testing) {
        test_check_password();
        test_crack_password();
    }
    if(argc != 2){
        printf("Usage: %s <64-character-hex-string>\n", argv[0]);
        return 1;
    }
    unsigned char given_hash[32];
    hexstr_to_hash(argv[1], given_hash);
    char password[256]; 
    int found = 0;
    while (fgets(password, sizeof(password), stdin)) {
        password[strcspn(password, "\n")] = '\0';
        if (crack_password(password, given_hash)) {
            printf("Found password: SHA256(%s) = %s\n", password, argv[1]);
            found = 1;
            break;
        }
    }
    if (!found) {
        printf("Did not find a matching password\n");
    }
    return 0;
}
    
    