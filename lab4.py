import idaapi
import types
#from ida_gdl import *
from idautils import *
from idc import *
import graphviz

use = []
defi = []
addrs = []
l1 = []
fin_dict = {}
output = {}
fin_new = {}

class myplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"
    help = "This is help"
    wanted_name = "Venera plugin"
    wanted_hotkey = "Alt-F8"

    def print_path(self, u, parent, all_paths):
        path = []
        while (u != -1):
            path.append(u)
            u = parent[u]
        path.reverse()
        all_paths.append(path)
        #print(path)     

    def dfs_iterative(self, graph, start, all_paths):
        stack = [(start, -1)]
        path = []
        parent = {}
        parent[start] = -1
        while stack:
            vertex, p = stack.pop()
            parent[vertex] = p
            path.append(vertex)
            isLeaf = True
            if vertex not in graph:
                graph[vertex] = []
            for neighbor in graph[vertex]:
                if neighbor not in path:
                    parent[neighbor] = vertex
                    isLeaf = False
                    stack.append((neighbor, vertex))
            if isLeaf:
                myplugin_t.print_path(self, vertex, parent, all_paths)
                if not stack:
                    break
                while path[-1] != stack[-1][1]:
                    path.pop()

    def shadowstack(self, line, listPush):
        m = idc.print_insn_mnem(line)
        temp1 = []
        if m == "push":
            listPush.append(hex(line))
            #print("LINE 0x%x" %(line))
        #print(listPush)
        
        if m == "pop":
            if len(listPush)!=0:
                temp1 = listPush.pop()
                #print("POP SHADOW VALUE 0x%x - %s" %(line, temp1))
        
        if m == "call":
            temp = idaapi.get_arg_addrs(line)
            #print(" CALL LINE %s" %(temp))
            if temp is not None:
                for item in temp:
                    temp1.append(hex(item))
                    if hex(item) in listPush:
                        listPush.remove(hex(item))
                    else:
                        pass
                        #print("ITEM NOT IN THE LIST", hex(item) )
                    #print("CALL SHADOW VALUE 0x%x - 0x%x" %(line, item))
            #else:
                #temp1.append(' ')
                    
        return temp1


    def dd(self, dism_addr, func_start, func_end, dict_def2,dict_def, dict_use, last_occ, listPush):
        dict_def = {"NON": "Start"}
        opt = {
            "BL" : "EBX",
            "AL" : "EAX",
            "CL" : "ECX",
            "DL" : "EDX",
            "DI" : "EDI",
            "SI" : "ESI"
        }
        t = []
        for line in dism_addr: 
            #print("LINE: ", line)
            t.append(hex(line))
            cur_addr = func_start
            next_addr = idc.next_head(line,func_end)


            while hex(line) > hex(cur_addr):
                for key,value in dict_def2.items():
                    r2 = dict_def2[cur_addr]
                    r2 = r2.split(',')
                    for element in r2:
                        dict_def[element] = hex(cur_addr)
                cur_addr = idc.next_head(cur_addr,func_end)
        
            
            #print(dict_def)
            #print(dict_use)
            #print(dict_use.values())        
            #print(dict_use[hex(line)])
            str1 =[]
            

            for item in dict_use[hex(line)]:
                #print(dict_use['0x402b64'])
                k = myplugin_t.shadowstack(self,line, listPush)
                
                if len(k) !=0:
                    #print(k)
                    if 'list' in str(type(k)):
                        for v in k:
                            if v not in str1:
                                str1.append(v)
                            #print(str1)
                    else:
                        str1.append(k)
                        #print(str1)

                    
                    if dict_use[hex(line)] == ['']:
                        last_occ[hex(line)] = str1
                if idc.print_insn_mnem(line) == "test":
                    if dict_use[hex(line)] == ['']:
                        last_occ[hex(line)] = ' '

                    
                    #print(str1)
                if item in dict_def.keys():
                    if len(item)>1:
                        if dict_def[item] not in str1:
                            str1.append(dict_def[item])
                        last_occ[hex(line)] = str1
                        
                        #print("VALUE USE {}  VALUE DEF {}".format(hex(line), dict_def[item]))
                else:
                    if item in opt.keys():
                        #print(opt[item] + " " + hex(line))
                        if opt[item] in dict_def.keys():
                            str1.append(dict_def[opt[item]])
                            last_occ[hex(line)] = str1
                            
                    else:
                        str1.append(dict_def["NON"])
                        last_occ[hex(line)] = str1
                    
                    #print("VALUE USE {}  VALUE DEF {}".format(hex(line), dict_def["NON"]))
        myplugin_t.compare(self, last_occ, t)
                #for key, value in last_occ.items():
                    #pass
                    #print("KEY {} , VALUE {}".format(key,value) )
                    
    def compare(self, dic, t):
        global output
        
        if not output:
            output = dic

        for addr in t:
            if addr in output:
                tmp_out = output[addr]
            else:
                output[addr] = []
                tmp_out = output[addr]
            tmp_dic = dic[addr]
            if tmp_dic != tmp_out:
                for item in tmp_dic:
                    if item not in tmp_out:
                        tmp_out.append(item)
                output[addr] = tmp_out
        #print("NEW RUN")
        #for key, values in output.items():
            #print("ADDRESS: {}, VALUE: {}".format(key, values))


    def init(self):
        return idaapi.PLUGIN_OK

    def run(self,arg):
        global l1
        global output

        for i in range(0,1):

            func_main = idaapi.get_func(int("401406", 16))
            func_start = func_main.start_ea # start of the function
            func_end = func_main.end_ea -1 # end of the function
            cur_addr = func_start
            dot = graphviz.Digraph(comment="digraph")
            i1 = 1
            my_dict = {}
            dict_use = {}
            dict_def = {"NON": "Start"}
            dict_def2 = {}
            last_occ = {}
            graph = {}
            all_paths = []
            l1 = []
            listPush=[]
            #l1.append(hex(func_start))
            jumps = ['jmp', 'jb', 'jbe' ,'jnz' ,'jz' ,'ja' ,'je' ,'jne' ,'jg' ,'jnle' ,'jge' , 'jnl' ,'jl' ,'jnge' ,'jle' ,'jng' ,'jnbe' ,'jae' ,'jnb' ,'jnae', 'jna']
            dism_addr = list(FuncItems(func_start)) # list of all the asm commands in the function 
            
            for line in dism_addr:
                mnem = idc.print_insn_mnem(cur_addr) # gets the mnemonic of the current instruction
                line1 = idc.generate_disasm_line(cur_addr,0) # gets the whole instruction
                flag = 0
                
                if mnem in jumps:
                    new_addr = idc.print_operand(cur_addr,0)
                    #new_addr = idc.generate_disasm_line(cur_addr,1)
                    new_addr = ("0x" + new_addr[-6:]).lower()
                    if mnem == 'jmp':
                        flag = 2
                    else:
                        flag = 1
                if flag is not 2:
                    l1.append(str(hex(cur_addr)))
                    l1.append(str(hex(idc.next_head(cur_addr,func_end))))
                if flag is 1 or flag is 2:
                    if mnem == "jmp" and idc.get_operand_type(cur_addr,0) == 2:
                        l1.append(str(hex(cur_addr)))
                        l1.append(str(hex(idc.next_head(cur_addr,func_end))))
                    else:
                        l1.append(str(hex(cur_addr)))
                        l1.append(str(new_addr))
                #print(l1)
                                

                op_type = idc.get_operand_type(line,0) # gets the type of operand and each return value represents a different operand type
                str_def = "D:"
                str_use = "U:"
                #str_def = ""
                #str_use = ""
                j=0
                str_temp = ""

                if mnem == 'push':
                    str_def += 'ESP,[ESP]'
                    str_use += 'ESP'
                 
                    if op_type == 1 or op_type ==2:
                        
                        str_use += ',' + idc.print_operand(line,0).upper()
                    if op_type == 4: 
                        str_temp = idc.print_operand(line,0).upper()
                        for elem in range(0,len(str_temp)):
                            if str_temp[elem] == '[':
                                str_use += ',' + str_temp + "," + str_temp[elem+1:elem+4]
                    if op_type == 3:
                        str_use += ',' + idc.print_operand(line,0).upper() + ',' + idc.print_operand(line,0).upper()[11:14]

                if mnem == 'pop':
                    str_use += 'ESP'
                    if op_type == 1:
                        str_def += 'ESP,' + idc.print_operand(line,0).upper()
                            
                if mnem == "cmp":
                    str_def+="EFLAGS"
                    if idc.get_operand_type(line,1) == 3:
                        for i in idc.print_operand(line,1).upper():
                            j+=1
                            if i == "[":
                                str_temp = idc.print_operand(line,1).upper()[j:j+3] + "," + idc.print_operand(line,1).upper()[j+4:j+7]
                        str_use += idc.print_operand(line,0).upper() + "," + idc.print_operand(line,1).upper() + "," + str_temp
                    elif idc.get_operand_type(line,1) == 4:
                        for i in idc.print_operand(line,1).upper():
                            j +=1
                            if i == "[":
                                str_temp = idc.print_operand(line,1).upper()[j:j+3]
                        str_use += idc.print_operand(line,0).upper() + "," + idc.print_operand(line,1).upper() + "," + str_temp
                    elif idc.get_operand_type(line,1) == 5:
                        str_use += idc.print_operand(line,0).upper()
                    else:
                        str_use +=idc.print_operand(line,0).upper() + "," + idc.print_operand(line,1).upper()
                    if op_type == 3 or idc.print_operand(line,0).upper() == "BYTE PTR [EAX+ESI+1]" or idc.print_operand(line,0).upper() == "BYTE PTR [EAX+ESI+2]" or idc.print_operand(line,0).upper() == "BYTE PTR [EAX+ESI+3]":
                        for i in idc.print_operand(line,0).upper():
                            j+=1
                            if i == "[":
                                str_temp= idc.print_operand(line,0).upper()[j:j+3] + "," + idc.print_operand(line,0).upper()[j+4:j+7] 
                        str_use += "," + str_temp
                    elif op_type == 4:
                        for i in idc.print_operand(line,0).upper():
                            j+=1
                            if i == "[":
                                str_temp = idc.print_operand(line,0).upper()[j:j+3]
                        str_use += "," + str_temp
                            
                if mnem == 'mov' or mnem == 'movzx' or mnem == 'movsx':
                    str_def += idc.print_operand(line,0).upper()
                    str_temp += idc.print_operand(line,1).upper()
                    if idc.get_operand_type(line,1) != 5:
                        str_use += idc.print_operand(line,1).upper()
                    if op_type == 2:
                        str_use += ","+idc.print_operand(line,0).upper()
                    if op_type is 4:
                        str_use += "," + str_def[3:6]
                    if op_type == 3:
                        if idc.print_operand(line,0).upper() == "DWORD PTR [ESI]":
                            str_use += str_def[13:16]
                        elif idc.print_operand(line,0).upper() == "BYTE PTR [EAX]":
                            str_use += str_def[12:15]
                        elif idc.print_operand(line,0).upper() == "[ESP+290H+VAR_290]":
                            str_use += str_def[3:6]
                        else:
                            str_use += "," + str_def[3:6] + "," + str_def[7:10]
                    if idc.get_operand_type(line, 1) == 4:
                        str_use += "," + str_temp[1:4]
                    if idc.get_operand_type(line, 1) == 3:
                        str_use += "," + str_temp[1:4] + "," + str_temp[5:8]

                if mnem == 'test':
                    str_def+="EFLAGS"
                    if op_type ==1:
                        str_use+=idc.print_operand(line,0).upper()
                    else:
                        str_use+=idc.print_operand(line,0).upper() + ","
                        strV=idc.print_operand(line,0).upper()
                        for i in strV:
                            j+=1
                            if i == "[":
                                str_use+=strV[j:j+3] + "," + strV[j-1:]      
                            
                if mnem == "call":
                    str_def += "ESP,EAX"
                    str_use += "ESP"
                    if op_type == 1:
                        str_use += "," + idc.print_operand(line,0).upper()
                    if op_type == 2:
                        #str_def+="," + "EAX"
                        str_use += "," + idc.print_operand(line,0).upper()
                            
                if mnem == "leave":
                    str_def+= "ESP,EBP"
                    str_use+= "EBP"
                    if mnem.startswith('j') and mnem!= "jmp":
                        str_use+="EFLAGS"

                if mnem == "and":
                    str_def+= "EFLAGS, " + idc.print_operand(line,0).upper()
                    if op_type == 4:
                        if idc.print_operand(line,0).upper()[0] == "[": 
                            str_use+= idc.print_operand(line,0).upper()[1:4]
                        elif idc.print_operand(line,0).upper() == "BYTE PTR [EAX+EDI+1]":
                            str_use+= idc.print_operand(line,0).upper()[10:13] + "," + idc.print_operand(line,0).upper()[14:17]
                        else:
                            str_use+=idc.print_operand(line,0).upper()[11:14]
                    elif op_type == 1:
                        str_use+=idc.print_operand(line,0).upper()
                    elif op_type == 3:
                        if idc.print_operand(line,0).upper() == "BYTE PTR [EAX]":
                            str_use+=idc.print_operand(line,0).upper()[10:13]
                        else:
                            str_use+=idc.print_operand(line,0).upper()[10:13] + "," + idc.print_operand(line,0).upper()[14:17]
                    else:
                        str_use+=idc.print_operand(line,0).upper()[10:13]
                
                if mnem == "add" or mnem == "sub":
                    if op_type == 1:
                        str_def+="EFLAGS," + idc.print_operand(line,0).upper()
                        str_use+=idc.print_operand(line,0).upper()
                    else:
                        str_def+="EFLAGS," + idc.print_operand(line,0).upper()[1:4]
                        str_use+=idc.print_operand(line,0).upper()[1:4]
                    if idc.get_operand_type(line,1) == 1:
                        str_use+="," + idc.print_operand(line,1).upper()
                    elif idc.get_operand_type(line,1) == 5:
                        str_use+=""
                    else:
                        str_use+="," + idc.print_operand(line,1).upper()[1:4]    
                
                if mnem == "xor" or mnem == "sar" or mnem == "dec" or mnem == "inc" or mnem == "or" or mnem == "imul" or mnem == "shr":
                    if op_type == 1 or op_type == 2:
                        str_def+="EFLAGS," + idc.print_operand(line,0).upper()
                        str_use+= idc.print_operand(line,0).upper()
                    else:
                        str_def+="EFLAGS," + idc.print_operand(line,0).upper()[1:4]
                        str_use+=idc.print_operand(line,0).upper()[1:4] 
                
                if mnem == 'stosd':
                    str_def += '[EDI],ECX,EDI'
                    str_use += 'EDI,ECX,EFLAGS'
                    
                if mnem == "retn":
                    str_def += "ESP,EIP"
                    str_use += "ESP"
                if mnem == "lea": 
                    str_def += idc.print_operand(line,0).upper()
                    addr = idc.print_operand(line,1).upper()
                    str_use += addr[1:4]
                    if addr == "[ESI+EDI]":
                        str_use += "," + addr[5:8]
                    c=0
                    for i in addr:
                        if i=="+":
                            c+=1
                    if c==2:
                        str_use += "," + addr[5:8] 
                if mnem == 'setnz':
                    str_use += "EFLAGS"
                    str_def += idc.print_operand(line,0).upper()
                if mnem in jumps:
                    str_use += 'EFLAGS'
                    if mnem =="jmp":
                        if op_type == 2:
                            str_use += "," + idc.print_operand(line,0).upper()
                cur1_addr = cur_addr
                n = 'n'+ str(i1)
                cur1_addr = str(hex(cur1_addr))
                
                cur1_addr += " " + str_def + "--" + str_use 
                my_dict[n] = cur1_addr
                #print(my_dict)
                str_def = str_def[2:]
                dict_def2[cur_addr] = str_def
                
                i1 = i1 + 1
                #r2 =str_use.split(':')
                #print(r2[1])
                str_use = str_use[2:]
                r1 = str_use.split(',')
                v = []
                for element in r1[0:]:
                    
                    v.append(element)
                    #print("ELEMENT, V", element, v)
                    dict_use[hex(cur_addr)] = v
                cur_addr = idc.next_head(cur_addr,func_end)

            while "0xffffffff" in l1:
                l1.remove("0xffffffff")
            t = []
            
            for x in l1:
                t.append(int(x, 16))
            
            #print(l1)
            for i in range(0, len(t)-2, 2):
                temp = [t[i+1]]
                if t[i] in graph:
                    temp = [graph[t[i]][0], t[i+1]]
                    graph[t[i]] = temp
                else:
                    graph[t[i]] = temp

            #print(graph)

            #func_main = idaapi.get_func(4205231)
            #func_start = func_main.start_ea # start of the function
            #func_end = func_main.end_ea -1 # end of the function
            #dism_addr = list(FuncItems(func_start)) # list of all the asm commands in the function
            myplugin_t.dfs_iterative(self, graph, func_start, all_paths)
            #print(all_paths)
            for path in all_paths:
                #print("DIFFERENT PATH")
                myplugin_t.dd(self, path, func_start, func_end, dict_def2, dict_def, dict_use, last_occ, listPush)
            print(output)
                
            
            """
            for key,value in my_dict.items():
                dot.node(key,value)
            list_len = len(l1)
                
            for k in range(0,list_len-1,2):
                for key,value in my_dict.items():
                    if l1[k] == value[0:8]:
                        for key1,value1 in my_dict.items():
                            if l1[k+1] == value1[0:8]:
                                dot.edge(key,key1)   
            #print(dot.source)
            """
        
        dict_i = 1    
        for line in dism_addr:
            n = "n"
            l_new = []
            
            n_new = n + str(dict_i)
                #print(n_new)
            fin_new[n_new] = str(hex(line))
            dict_i = dict_i + 1
            
        #print(fin_new)
        fin_new['n0'] = 'Start'
        for key,value in output.items():
            for key1, value1 in fin_new.items():
                st = ""
                if value1 == key:
                    if len(value) == 1:
                        st = value[0]
                    else:
                        for item in value:
                            if st == "":
                                st += item
                            else:
                                st += "," + item
                    s1 = "{}; DD:{}".format(value1,st)
                    dot.node(str(key1),s1)
        
        
        #print(fin_new) 
        for key,value in output.items():
            nb = key
            for key1,value1 in fin_new.items():
                if value1 == key:
                    nb = key1
            for item in value:
                if len(item) > 1:
                    for key1, value1 in fin_new.items():
                    #na = 'Start'
                        if len(item) > 1 and item == value1:
                            na = key1
                else:
                    v = 'Start'
                    if v == value1:
                        na = key1
                dot.edge(nb,na)

        file_name = '/nethome/vmakhambayeva3/{}.dot'.format(idc.get_func_name(func_start))
        f = open(file_name,'w')       
        f.write(dot.source)
        #print(dot.source)
        #print(fin_new)
        #print(fin)

        

    def term(self):
        pass

def PLUGIN_ENTRY():
    return myplugin_t()