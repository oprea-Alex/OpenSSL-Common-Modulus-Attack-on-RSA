# OpenSSL-Common-Modulus-Attack-on-RSA
C implementation of the Common Modulus Attack using OpenSSL open-source library.



Write Up(RO):


	Din descrierea protocolului am observat ca la criptare, atat cu cheia public atacata(cu bit schimbat in exponent), cat si la cea corecta a server-ului singurul care va diferi va fi exponentul public, modulul ramand constant => Problema se preteaza atacului Common Modulus asupra RSA.
	
	Atacul presupune exploatarea vulnerabilitatilor introduse la criptarea cu acelasi modul in cheia publica.
	Rationamentul matematic:
		Din identitatea Bezout (e1 * a) + (e2 * b) = GCD(e1, e2) putem obtine coeficientii Bezout a si b.
		Avand captate ambele ciphertext-uri, aplicam:
		c1^a mod n = m^(c1*a) mod n
		c2^b mod n = m^(c2*b) mod n
		Inmultind cele 2 ecuatii intre ele, =>:
		c1^a * c2^b mod n = m^(c1*a + c2*b) mod n = m^GCD(e1,e2) mod n (Din identitatea Bezout)
		Deci, daca rezultatul inmultirii are la exponent GCD(e1,e2), si tinand cont ca noi putem profita de faptul ca putem modifica ORICE bit din exponentul e2 => il modificam in favoare noastra: a.i. GCD(e1,e2)=1
		
		
	In continuare, am recurs la incarcarea cheii din .docx intr-un fisier regular, pe care l-am citit cu utilitarul openssl:
	Cu comanda openssl.exe rsa -pubin -in .\key.pub -text -modulus am extras e1 = 5 si modulul cheii pe care l-am pus in fisierul modulus.in.
	Dupa ce am incarcat si ambele fisiere in cipher1.in si cipher2.in, am implementat in BN-uri rationamentul matematic de mai sus. A fost nevoie sa merg prin incercari pentru a determina e2. Prima optiune a fost e=3,dar nu producea niciun output inteligibil. Asa ca urmatorul e incercat a fost e2=7.
	
	In file.out, programul scoate mesajul in hexa:
	5468652052534127732074657874626F6F6B206D6F646520697320636F6D706C6574656C7920696E7365637572652E20546869732069732077687920525341206E6565647320612072616E646F6D697A65642070616464696E6720736368656D6521
	
	fiind nevoie o conversie HEX -> ASCII pe care am facut-o cu Pugin-ul din Notepad++:
	
	The RSA's textbook mode is completely insecure. This is why RSA needs a randomized padding scheme!
	


