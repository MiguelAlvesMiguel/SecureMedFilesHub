Como executar o trabalho:

Servidor
myCloudServer 23456

Cliente:
Comando C:
	myCloud -a <serverAddress> -u <username> -p <password> -c {<filenames>}+
Comando au:
	myCloud -a <serverAddress> -au <username> <password> <certificado>
Comando -s:
	myCloud -a <serverAddress> -u <username> -p <password> -s {<filenames>}+
Comando -e:
	myCloud -a <serverAddress> -u <username> -p <password> -e {<filenames>}+
Comando -g:
	myCloud -a <serverAddress> -u <username> -p <password> -g {<filenames.assinado OU filenames.cifrado>}+