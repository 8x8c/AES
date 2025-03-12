# a simple command-line utility for encrypting or decrypting files using XChaCha20-Poly1305

It is not about the name! You can change the default name in Cargo.toml before you compile or simply rename the executable after it is compiled. 

A key is often better than a password. So should an encryption app use a password or key? I solved that question with a nice design choice. The app always relies on a key, but you can make the same key from the same password (deterministic key). Near the top of main.rs you can salt the key gen, so a password would made a different key for each salt! That is an awesome solution. You can use any third party app to make a 32 byte key file also. You can change the salt and the key name in main.rs before you compile. 

# Keygen
aes-cli --keygen  asks for a password, makes a key, or you can put any key in the same directory as the executable. 

# Encrypt or Decrypt a file. 

./aes-cli --E api.html out.html

./aes-cli --D out.html apidecrypted.html




# Atomic In-Place Overwrite

./aes-cli --E --over <file>
./aes-cli --D --over <file>


That is it! This app has simple input commands but it can do a lot! It is an all in one encryption app solution! Key maker, password, no pasword, always uses a key, make another file or overwrite in place. That is a great set of features for a single encryption app! 



