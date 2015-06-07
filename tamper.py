# -*- coding: cp936 -*-
##import tamper script
# from tamper.apostrophenullencode import tamper
import sys;
if not "tamper/" in sys.path:
    sys.path.append("tamper/")

import apostrophemask
import apostrophenullencode
import appendnullbyte
import base64encode
import between
import bluecoat
import chardoubleencode
import charencode
import charunicodeencode
import concat2concatws
import equaltolike
import greatest
import halfversionedmorekeywords
import ifnull2ifisnull
import lowercase
import modsecurityversioned
import modsecurityzeroversioned
import multiplespaces
import nonrecursivereplacement
import overlongutf8
import percentage
import randomcase
import randomcomments
import securesphere
import sp_password
import space2comment
import space2dash
import space2hash
import space2morehash
import space2mssqlblank
import space2mssqlhash
import space2mysqlblank
import space2mysqldash
import space2plus
import space2randomblank
import unionalltounion
import unmagicquotes
import varnish
import versionedkeywords
import versionedmorekeywords
import xforwardedfor

#TAMPER_NAME = ["apostrophemask","apostrophenullencode","appendnullbyte","base64encode","between","bluecoat","chardoubleencode","charencode","charunicodeencode","concat2concatws","equaltolike","greatest","halfversionedmorekeywords","ifnull2ifisnull","lowercase","modsecurityversioned","modsecurityzeroversioned","multiplespaces","nonrecursivereplacement","overlongutf8","percentage","randomcase","randomcomments","securesphere","sp_password","space2comment","space2dash","space2hash","space2morehash","space2mssqlblank","space2mssqlhash","space2mysqlblank","space2mysqldash","space2plus","space2randomblank","unionalltounion","unmagicquotes","varnish","versionedkeywords","versionedmorekeywords","xforwardedfor"]
INPUT_PATH = "./sql-injection/"
INPUT_FILE_NAME = sys.argv[1]
OUTPUT_PATH = "mutation"
OUTPUT_FILE_NAME = ''.join([OUTPUT_PATH,"/",INPUT_FILE_NAME,"_mutation"])

def mutation():
    ##read input file
    #INPUT_FILE = INPUT_FILE_NAME+".txt"
    INPUT_FILE = ''.join([INPUT_PATH,INPUT_FILE_NAME,".txt"])
    file_input = open(INPUT_FILE)
    try:
        lines = file_input.readlines()
    finally:
        file_input.close()

    ##Read output file
    OUTPUT_FILE = ''.join([OUTPUT_FILE_NAME,".txt"])
    file_output = open(OUTPUT_FILE,"w+")

    #print len(TAMPER_NAME)
    ##Mutation the input file
    i = 0
    for  input_line in lines :
        #file_output = open(OUTPUT_FILE,"a")
        i += 1
        output_line = {}
        input_line = input_line.strip()
        if (input_line != ""):
            output_line[0]	=	apostrophemask.tamper(input_line)
            output_line[1]	=	apostrophenullencode.tamper(input_line)
            output_line[2]	=	appendnullbyte.tamper(input_line)
            # output_line[3]	=	base64encode.tamper(input_line)
            output_line[4]	=	between.tamper(input_line)
            output_line[5]	=	bluecoat.tamper(input_line)
            output_line[6]	=	chardoubleencode.tamper(input_line)
            output_line[7]	=	charencode.tamper(input_line)
            output_line[8]	=	charunicodeencode.tamper(input_line)
            output_line[9]	=	concat2concatws.tamper(input_line)
            output_line[10]	=	equaltolike.tamper(input_line)
            output_line[11]	=	greatest.tamper(input_line)
            output_line[12]	=	halfversionedmorekeywords.tamper(input_line)
            output_line[13]	=	ifnull2ifisnull.tamper(input_line)
            output_line[14]	=	lowercase.tamper(input_line)
            output_line[15]	=	modsecurityversioned.tamper(input_line)
            output_line[16]	=	modsecurityzeroversioned.tamper(input_line)
            output_line[17]	=	multiplespaces.tamper(input_line)
            output_line[18]	=	nonrecursivereplacement.tamper(input_line)
            output_line[19]	=	overlongutf8.tamper(input_line)
            output_line[20]	=	percentage.tamper(input_line)
            output_line[21]	=	randomcase.tamper(input_line)
            output_line[22]	=	randomcomments.tamper(input_line)
            output_line[23]	=	securesphere.tamper(input_line)
            output_line[24]	=	sp_password.tamper(input_line)
            output_line[25]	=	space2comment.tamper(input_line)
            output_line[26]	=	space2dash.tamper(input_line)
            output_line[27]	=	space2hash.tamper(input_line)
            output_line[28]	=	space2morehash.tamper(input_line)
            output_line[29]	=	space2mssqlblank.tamper(input_line)
            output_line[30]	=	space2mssqlhash.tamper(input_line)
            output_line[31]	=	space2mysqlblank.tamper(input_line)
            output_line[32]	=	space2mysqldash.tamper(input_line)
            output_line[33]	=	space2plus.tamper(input_line)
            output_line[34]	=	space2randomblank.tamper(input_line)
            output_line[35]	=	unionalltounion.tamper(input_line)
            output_line[36]	=	unmagicquotes.tamper(input_line)
            # output_line[37]	=	varnish.tamper(input_line)
            output_line[37]	=	versionedkeywords.tamper(input_line)
            output_line[38]	=	versionedmorekeywords.tamper(input_line)
            output_line[40]	=	xforwardedfor.tamper(input_line)

            ## orign line
            # output_line[41] = input_line

            try :
                output_line[3]  =   base64encode.tamper(input_line)
            except:
                print "[",i,"] base64encode Failed"
            finally:
                pass

            ##Write mutation into file
            try:
                output_line = [ output_line[line].strip() + '\n' if line != 2 else output_line[line] +'\n' for line in output_line.keys()   ]
                file_output.writelines(output_line)
                print "[",i,"] Mutation Successfully"
            except:
                print "[",i,"] Mutation Failed:",input_line
    ##        finally:
    ##            file_output.close()

    file_output.close()

    PurgeOutput(OUTPUT_FILE_NAME)

def PurgeOutput( OUTPUT_FILE_NAME ):
    OUTPUT_FILE = ''.join([OUTPUT_FILE_NAME,".txt"])
    PURGEOUTPUT_FILE = ''.join([OUTPUT_FILE_NAME,"_purge",".txt"])
    origal_output = open(OUTPUT_FILE)
    purge_output = open(PURGEOUTPUT_FILE,"w+")
    try:
        lines = origal_output.readlines()
        # print type(lines)
        # lines = ''.join(set(lines))        
        # lines.sort

        lines_purge = list(set(lines))
        # lines_purge.sort(key=lines.index)
        lines_purge = ''.join(lines_purge)
        purge_output.write(lines_purge)
        print "Purge Successfully"
    except:
        print "Purge Failed"
    finally:
        origal_output.close()
        purge_output.close()

if __name__ == '__main__':
    mutation()
    #print tamper("1 AND '1'='1")
