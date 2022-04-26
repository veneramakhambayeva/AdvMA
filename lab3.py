import idaapi
import types
from idautils import *
from idc import *
import graphviz

class myplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"
    help = "This is help"
    wanted_name = "My Python plugin"
    wanted_hotkey = "Alt-F8"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):

        print ("Hello world!")
        for func in Functions():
            my_dict={}
            flags = idc.get_func_attr(func, FUNCATTR_FLAGS)
            if flags & FUNC_STATIC or flags & FUNC_FRAME or flags == 21504 :
                filename= idc.get_func_name(func)+".dot"
                #content=""
                printcontent ="//" + idc.get_func_name(func) + "\n" + "digraph {" +"\n"
                #print(content)
                #dot = graphviz.Digraph(comment=idc.get_func_name(func))
                num = 0
                content=""
                dism_addr = list(FuncItems(func))
                for line in dism_addr:
                    num += 1
                    index = "n" + str(num)
                    my_dict[hex(line)] = index
                    strD = "D:"
                    strU = "U:"
                    j=0
                    m = idc.print_insn_mnem(line)
                    if m == "push":
                        strD+="[ESP],ESP"
                        strU+="ESP"
                        if idc.get_operand_type(line,0) == 1:
                            strU+="," + idc.print_operand(line, 0).upper()
                        if idc.get_operand_type(line,0) == 3:
                            strU+="," + idc.print_operand(line, 0).upper() + "," + idc.print_operand(line, 0).upper()[11:14]

                        if idc.get_operand_type(line,0) == 4:
                            strU+="," + idc.print_operand(line, 0).upper()
                            for i in idc.print_operand(line,0).upper():
                                j+=1
                                if i == "[":
                                    strV = idc.print_operand(line,0).upper()[j:j+3]
                            strU+="," + strV
                    if m == "stosd":
                        strD+="[EDI], ECX, EDI"
                        strU+= "EDI, ECX, EFLAGS"
                    if m == "setnz":
                        strD+=idc.print_operand(line,0).upper()
                        strU+= "EFLAGS"    
                    if m == "pop":
                        strD+= idc.print_operand(line,0).upper() + "," + "ESP"
                        strU+="[ESP],ESP" 
                    if m == "mov" or m =="movzx" or m =="movsx":
                        strD+=idc.print_operand(line,0).upper()
                        strV=idc.print_operand(line,1).upper()
                        if idc.get_operand_type(line,1) !=5:
                            strU+=idc.print_operand(line,1).upper()
                        if idc.get_operand_type(line,0) == 4:
                            strU+="," + strD[3:6]
                        if idc.get_operand_type(line,0) == 3:
                            if idc.print_operand(line,0).upper() == "DWORD PTR [ESI]":
                                strU+=strD[13:16]
                            elif idc.print_operand(line,0).upper() == "BYTE PTR [EAX]":
                                strU+=strD[12:15]
                            elif idc.print_operand(line,0).upper() == "[ESP+290H+VAR_290]":
                                strU+=strD[3:6]
                            else:
                                strU+="," + strD[3:6] + "," + strD[7:10]
                        if idc.get_operand_type(line,1) == 4:
                            strU+="," + strV[1:4]
                        if idc.get_operand_type(line,1) == 3:
                            strU+="," + strV[1:4] + "," + strV[5:8]
                    if m == "cmp":
                        strD+="EFLAGS"
                        if idc.get_operand_type(line,1) == 3:
                            for i in idc.print_operand(line,1).upper():
                                j+=1
                                if i == "[":
                                    strV = idc.print_operand(line,1).upper()[j:j+3] + "," + idc.print_operand(line,1).upper()[j+4:j+7]
                            strU+= idc.print_operand(line,0).upper() + "," + idc.print_operand(line,1).upper() + "," + strV 
                        elif idc.get_operand_type(line,1) == 4:
                            for i in idc.print_operand(line,1).upper():
                                j+=1
                                if i == "[":
                                    strV = idc.print_operand(line,1).upper()[j:j+3]
                            strU+= idc.print_operand(line,0).upper() + "," + idc.print_operand(line,1).upper() + "," + strV
                        elif idc.get_operand_type(line,1) == 5:
                            strU+= idc.print_operand(line,0).upper()
                        else:
                            strU+=idc.print_operand(line,0).upper() + "," + idc.print_operand(line,1).upper()
                        if idc.get_operand_type(line,0) == 3 or idc.print_operand(line,0).upper() == "BYTE PTR [EAX+ESI+1]" or idc.print_operand(line,0).upper() == "BYTE PTR [EAX+ESI+2]" or idc.print_operand(line,0).upper() == "BYTE PTR [EAX+ESI+3]":
                            for i in idc.print_operand(line,0).upper():
                                j+=1
                                if i == "[":
                                    strV= idc.print_operand(line,0).upper()[j:j+3] + "," + idc.print_operand(line,0).upper()[j+4:j+7] 
                            strU+= "," + strV
                        elif idc.get_operand_type(line,0) == 4:
                            for i in idc.print_operand(line,0).upper():
                                j+=1
                                if i == "[":
                                    strV = idc.print_operand(line,0).upper()[j:j+3]
                            strU+="," + strV
            
                    if m == "test":
                        strD+="EFLAGS"
                        if idc.get_operand_type(line,0) ==1:
                            strU+=idc.print_operand(line,0).upper()
                        else:
                            strU+=idc.print_operand(line,0).upper() + ","
                            strV=idc.print_operand(line,0).upper()
                            for i in strV:
                                j+=1
                                if i == "[":
                                    strU+=strV[j:j+3]        
                    if m == "call":
                        strD+="ESP"
                        strU+="ESP"
                        if idc.get_operand_type(line,0) != 2:
                            strD+="," + "EAX"
                        if idc.get_operand_type(line,0) == 1:
                            strU+="," + idc.print_operand(line,0).upper()
                    if m == "leave":
                        strD+= "ESP, EBP"
                        strU+= "EBP"
                    if m.startswith('j') and m!= "jmp":
                        strU+="EFLAGS"
                    if m == "and":
                        strD+= "EFLAGS, " + idc.print_operand(line,0).upper()
                        if idc.get_operand_type(line,0) == 4:
                            if idc.print_operand(line,0).upper()[0] == "[": 
                                strU+= idc.print_operand(line,0).upper()[1:4] + "," + idc.print_operand(line,0).upper()
                            elif idc.print_operand(line,0).upper() == "BYTE PTR [EAX+EDI+1]":
                                strU+= idc.print_operand(line,0).upper()[10:13] + "," + idc.print_operand(line,0).upper()[14:17] + "," + idc.print_operand(line,0).upper()
                            else:
                                strU+=idc.print_operand(line,0).upper()[11:14] + "," + idc.print_operand(line,0).upper()
                        elif idc.get_operand_type(line,0) == 1:
                            strU+=idc.print_operand(line,0).upper()
                        elif idc.get_operand_type(line,0) == 3:
                            if idc.print_operand(line,0).upper() == "BYTE PTR [EAX]":
                                strU+=idc.print_operand(line,0).upper()[10:13] +","+ idc.print_operand(line,0).upper()
                            else:
                                strU+=idc.print_operand(line,0).upper()[10:13] + "," + idc.print_operand(line,0).upper()[14:17] + "," + idc.print_operand(line,0).upper()
                        else:
                            strU+=idc.print_operand(line,0).upper()[10:13] + ","+ idc.print_operand(line,0).upper()
                    if m == "add" or m == "sub":
                        if idc.get_operand_type(line,0) == 1:
                           strD+="EFLAGS," + idc.print_operand(line,0).upper()
                           strU+=idc.print_operand(line,0).upper()
                        else:
                            strD+="EFLAGS," + idc.print_operand(line,0).upper()
                            strU+=idc.print_operand(line,0).upper()[1:4] + "," + idc.print_operand(line,0).upper()
                        if idc.get_operand_type(line,1) == 1:
                           strU+="," + idc.print_operand(line,1).upper()
                        elif idc.get_operand_type(line,1) == 5:
                            strU+=""
                        else:
                            strU+="," + idc.print_operand(line,1).upper()[1:4] + "," + idc.print_operand(line,1).upper()   
                    if m == "xor" or m == "sar" or m == "dec" or m == "inc" or m == "or" or m == "imul" or m == "shr":
                        if idc.get_operand_type(line,0) == 1 or idc.get_operand_type(line,0) == 2:
                            strD+="EFLAGS," + idc.print_operand(line,0).upper()
                            strU+= idc.print_operand(line,0).upper()
                        else:
       
                            strD+="EFLAGS," + idc.print_operand(line,0).upper()
                            strU+=idc.print_operand(line,0).upper()[1:4] + "," +  idc.print_operand(line,0).upper()
                    if m == "jmp":
                        if idc.get_operand_type(line,0) == 2:
                            strU+=idc.print_operand(line,0).upper()
                    if m == "retn":
                        strD+= "ESP, EIP"
                        strU+= "ESP"
                    if m == "lea": 
                        strD+=idc.print_operand(line,0).upper()
                        strV=idc.print_operand(line,1).upper()
                        strU+=strV + "," +strV[1:4]
                        if strV=="[ESI+EDI]":
                            strU+=","+strV[5:8]
                        c=0
                        for i in strV:
                            if i=="+":
                                c+=1
                        if c==2:
                           strU+=","+strV[5:8]     
                    #print("n%d [label= %x %s %s]" % (num, line, strD, strU))
                    content="n"+ str(num) +"  [label=" + "\"" + "0x%08x"%(line) + ";" + strD + "," + strU +"\""+ "]" + "\n"
                    printcontent += content
                    print(content)
                dism_addr = list(FuncItems(func))
                #for line in dism_addr:
                startflag=0
                lstinsidx=""
                lst1 = []
                lst2 = []
                content=""     
                #print(my_dict)
                for line in dism_addr:
                    #print(hex(line))
                    if startflag==0:
                        lstinsidx=my_dict[hex(line)]
                        lst1.append(lstinsidx)
                        startflag=1
                    else:
                        content += lstinsidx + " -> "
                        lstinsidx = my_dict[hex(line)] 
                        lst2.append(lstinsidx)
                        content += lstinsidx + "\n"
                        m = idc.print_insn_mnem(line)
                        if m == "retn":
                            startflag=0
                        if m.startswith('j'):
                            if idc.get_operand_type(line,0) == 6 or idc.get_operand_type(line,0) == 7:
                                new_addr = idc.print_operand(line,0)
                                new_addr = ("0x" + new_addr[-6:]).lower()
                                #print(new_addr)
                                if new_addr in my_dict:
                                    content += my_dict[hex(line)] + " -> " + my_dict[new_addr] + "\n"
                                if m == "jmp":
                                    startflag=0
                printcontent += content+"\n}"               
                print(content)
                with open(filename, 'w') as file:
                    file.write(printcontent)
                #for key,value in my_dict.items():
                #    dot.node(value,key)
                #for l1,l2 in zip(lst1,lst2):
                #    dot.edge(l1,l2)
                #print(dot.source)
    def term(self):
        pass

def PLUGIN_ENTRY():
    return myplugin_t()

