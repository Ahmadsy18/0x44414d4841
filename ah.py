import pefile
from treelib import Node, Tree
from termcolor import *
from os import path
from argparse import *
from tabulate import *
argv = ArgumentParser(description="extructing all informations from binary")
argv.add_argument("-i",action='store_true',help="show all imports")
argv.add_argument("-f",required=True,type=str,help="path binary file")
argv.add_argument("-s",action="store_true",help="show the all sections")
ag = argv.parse_args()

class PE:

    file_name = ""
    pe=""
    def __init__(self,file_name):
        self.file_name = file_name
        self.pe = pefile.PE(self.file_name)
    def pee(self):
        if not hasattr(self.pe,'DIRECTORY_ENTRY_IMPORT'):
            print('not found any imoort')
            return False
        else:
            try :

                for x in self.pe.DIRECTORY_ENTRY_IMPORT:
                    tree = Tree()
                    res = x.dll.decode()
                    tree.create_node(colored(res,"blue"),res)
                    for c in x.imports:
                        res1 = c.name.decode()
                        tree.create_node(colored(res1,"green"),parent=res)
                    tree.show()
            except:
                pass
    def section(self):
        header = []
        data = [[colored('Virtual Address',"yellow")],[colored('Virtual Size',"yellow")],[colored('Raw-Size',"yellow")]]
        c = 0
        for x in self.pe.sections:
            header.append(colored(x.Name.decode("utf-8"),"red"))
            data[c].append(colored(hex(x.VirtualAddress),"green"))
            data[c+1].append(colored(hex(x.Misc_VirtualSize),"green"))
            data[c+2].append(colored(str(x.SizeOfRawData),"green"))
            if ".rsrc" in x.Name.decode("utf-8"):
                break
            elif ".edata" in x.Name.decode("utf-8"):
                break
            elif ".idata" in x.Name.decode("utf-8"):
                break
            elif ".rdata" in x.Name.decode("utf-8"):
                break

        print(tabulate(data,headers=header,tablefmt="grid"))
if __name__ == '__main__':
    #try:
        if path.isfile(ag.f):
            pe = PE(ag.f)
            if ag.i:
                pe.pee()
            if ag.s:
                pe.section()
        else:
            argv.print_help()
