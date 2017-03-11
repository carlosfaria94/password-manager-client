del keystore.jceks
keytool -genkeypair -storetype JCEKS -alias "asymm" -keyalg RSA -keysize 2048 -keypass "batata" -validity 180 -storepass "batata" -keystore keystore.jceks -dname "CN=SEC, OU=DEI, O=IST, L=Lisbon, S=Lisbon, C=PT"
keytool -genseckey -storetype JCEKS -keyalg AES -alias "symm" -keysize 128 -validity 180 -keystore keystore.jceks -storepass "batata" -keypass "batata"