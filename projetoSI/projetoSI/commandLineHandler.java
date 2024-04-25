package projetoSI;

import java.nio.file.FileSystemNotFoundException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;

public class commandLineHandler extends errorable {
	static HashMap<String,List<String>> parse(String[] args) throws Exception {
		if(args.length == 1) {
			if( args[0].equals("-h")) {
				System.out.println("Opcoes:\n\n"
						+ "-u <user_id> \t\t\t Identifica o utilizador.\n"
						+ "-p <passwd> \t\t\t Password para autenticar o utilizador <user_id>.\n"
						+ "-a <sv_address> \t\t Identifica o servidor.\n"
						+ "-c <user_id> <u_nome> <passwd> \t Envia para o servidor os ficheiros especificados cifrados e as respetivas chaves cifradas \n"
						+ "-s {<filename>,...} \t\t Envia para o servidor os ficheiros especificados e as respetivas assinaturas.\n"
						+ "-e {<filename>,...} \t\t Envia para o servidor os ficheiros especificados cifrados em envelopes seguros.\n"
						+ "-g {<filename>,...} \t\t Os ficheiros especificados sao decifrados e sao verificadas as assinaturas dos ficheiros previamente assinados.\n");
				return null;
			} else if(args[0].equals("-l")){
				throw new Exception(args[0]+" não pode ser usado sem a devida autenticação.");
			} else {
				throw new Exception(args[0]+" não é um parâmetro válido.");
			}
		}
		HashMap<String,List<String>> param = new HashMap<String,List<String>>();
		Predicate<String> flagValidator = Pattern.compile("^-[uapcedsegh]|-au|-cert$").asPredicate();
		Predicate<String> validArg = Pattern.compile("^[a-zA-Z0-9.:]*$|^'[^'][a-zA-Z0-9.:]*'$").asPredicate();
		List<Integer> flags = new ArrayList<Integer>();
		for (int ind = 0; ind < args.length; ind++) {
			if(flagValidator.test(args[ind])) {
				flags.add(ind);
			} 
		}
		int expected_args = 0;
		int received_args;
		for (Integer flag_index : flags) {
			String temp = args[flag_index];
			if("-u-a-p-au-d".contains(temp)) {
				if(flags.indexOf(flag_index)+1 < flags.size()) {
					received_args = (flags.get(flags.indexOf(flag_index)+1)-(flag_index+1));
				}else {
					received_args = args.length-(flag_index+1);
				}
				if(temp.equals("-au")) {
					expected_args = 3;
				} else {
					expected_args = 1;
				}
				if (expected_args != received_args) {
					error(args[flag_index]+": esperados "+String.valueOf(expected_args)+", recebidos "+String.valueOf(received_args)+" argumentos.\n",1);
				}
			} else {
				if(flags.indexOf(flag_index)+1 < flags.size()) {
					expected_args = (flags.get(flags.indexOf(flag_index)+1)-(flag_index+1));
				}else {
					expected_args = args.length-(flag_index+1);
				}
			}
			List<String> params = new ArrayList<String>();
			for(int i = flag_index+1 ;i <= flag_index+expected_args; i++) {
				if(validArg.test(args[i])) {
					params.add(args[i]);
				} else {
					throw new Exception("Parâmetro não conhecido: '"+args[i]+"'");
				}
			}
			if(param.containsKey(temp)) {
				System.err.println(temp+": Parâmetro repetido 2 vezes.");
				System.exit(1);	
			}
			param.put(temp,params);
		}
		if(!param.containsKey("-a")) {
			System.err.println("Parâmetros para conexão em falta: -a ");
			System.exit(1);
		} else if(!param.containsKey("-au")) { 
			if(!param.containsKey("-u") || !param.containsKey("-p")) {
				System.err.println("Parâmetros para autenticação em falta:[-u, -p]");
				System.exit(1);
			}
		} else {
			Set keys = new HashSet<>(param.keySet());
			keys.removeAll(Set.of("-a","-u","-p"));
			if(keys.size() < 1) {
				System.err.println("Não foi dado um parâmetro para realizar uma ação:[-c, -e, -s, -g, -au]");
				System.exit(1);
			} else if (keys.size() > 1) {
				System.err.println(keys.toString() + ": Parâmetros são mutualmente exclusivos.");
				System.exit(1);
			}
		}
		
		return param;
	}
}