import UsrIntel.R1
import json

class RedfishParse:

    def get_where_fields(arg):
        if '==' in arg:
            operator = "=="
        elif '!=' in arg:
            operator = "!="
        elif '=~' in arg:
            operator = "=~"
    
        field = str(arg).split(operator)[0]
        value = str(arg).split(operator)[1].split("'")[1]
    
        return(field,value,operator)
    
    def find_where(selection, args, count):
        args_where = (args[count])[0]
        operator = "<none>"
    
        all_blocks = []
        matched_array = []
        if '||' in args_where:
            for w in args_where.split('||'):
                field, value, operator = RedfishParse.get_where_fields(w)
                tmp_array = RedfishParse.match_blocks(field, value, operator, selection)
                if tmp_array not in all_blocks:
                    all_blocks.append(tmp_array)
        elif '&&' in args_where:
            tmp = []
            for w in args_where.split('&&'):
                field, value, operator = RedfishParse.get_where_fields(w)
                if tmp:
                    tmp_array = RedfishParse.match_blocks(field, value, operator, tmp)
                    tmp = []
                    for t in tmp_array:
                        tmp.append(t)
                else:
                    tmp_array = RedfishParse.match_blocks(field, value, operator, selection)
                    for t in tmp_array:
                        tmp.append(t)
            if tmp:
                all_blocks.append(tmp)
        else:
            field, value, operator = RedfishParse.get_where_fields(args_where)
            tmp_array = RedfishParse.match_blocks(field, value, operator, selection)
            all_blocks.append(tmp_array)
    
        if all_blocks:
            for i in all_blocks:
                for o in i:
                    matched_array.append(o)
    
        return(matched_array)
    
    def match_blocks(field, value, operator, selection):
        header = ""
        tmp_array1 = []
        tmp_array2 = []
        mark = 0
        select = 0
        for i in selection:
            str_array = str(i).split(':')
            in_field = str_array[0].strip()
            if len(str_array) > 1 and '::' not in i:
                in_value = str_array[1].strip()
            else:
                in_value = "<NO VALUE HERE>"
            if mark == 1:
                tmp_array2.append(i)
                if operator == '==':
                    if field.lower() == in_field.lower() and value.lower() == in_value.lower():
                        select = 1
                if operator == '!=':
                    if field.lower() == in_field.lower() and value.lower() != in_value.lower():
                        select = 1
                if operator == '=~':
                    if field.lower() == in_field.lower() and value.lower() in in_value.lower():
                        select = 1
                
            if '::' in i:
                header = i
            if '---------' in i and mark == 1:
                if select == 1:
                    if header not in tmp_array1:
                        tmp_array1.append(header)
                    tmp_array1.append('------------------------------')
                    for n in tmp_array2:
                        tmp_array1.append(n)
                else:
                    tmp_array2 = []
                mark = 0
                select = 0
            if '---------' in i and mark == 0:
                tmp_array2 = []
                mark = 1
    
        return(tmp_array1)
    
    def get_next_where(count, cmdline_args_order):
        next_args = ""
        s_count = 0
        w_count = 0
        mark = 0
        for c in cmdline_args_order:
            if (c == '-w' or c == '--where') and mark == 0:
                w_count += 1
            if (c == '-w' or c == '--where') and mark == 1:
                return(c,w_count)
            if (c == '-s' or c == '--show') and mark == 1:
                return(c,w_count)
            if (c == '-s' or c == '--show') and mark == 0:
                if int(s_count) == int(count):
                    mark = 1
                else:
                    s_count += 1
    
        return(next_args, w_count)
    
    def output_selection(selection, args_script, args_where, count, cmdline_args_order):
        if args_where:
            next_args, w_count = RedfishParse.get_next_where(count, cmdline_args_order)
    
            if next_args == '-w' or next_args == '--where':
                tmp_array1 = RedfishParse.find_where(selection, args_where, w_count)
            else:
                tmp_array1 = selection
        else:
            tmp_array1 = selection
                
        if args_script == "True":
            output = ""
            scripted_format = []
            for i in tmp_array1:
                if ':: ' not in i:
                    if i.split(': ')[-1] and '------------' not in i.split(': ')[-1]:
                        output += (i.split(': ')[-1]).replace(' ','') + " "
            
            output = output.rstrip()
            scripted_format.append(output)
            return(scripted_format)
        else:
            return(tmp_array1)
    
    def parse_hash(args_group,sys_dict):
        tmp = []
        if len(args_group) > 1:
            args_total_count = (len(args_group) - 1)
            if args_total_count > 0:
                all_args = args_group[1:]
                tmp2 = []
                tmp2.append("------------------------------")
                selection = RedfishParse.parse_blocks(args_total_count,all_args,tmp2,0,0,sys_dict)
                for i in selection:
                    tmp.append(i)
                tmp.append("------------------------------")
        else:
            print(args_group[0])
            print(json.dumps(sys_dict,indent=4))

        if len(tmp) <= 2 and len(args_group) > 1:
            return(["No Output"])
        else:
            return(tmp)

    def parse_blocks(args_group_count,args_group,selection,group_counter,sub_group_counter,sel_sys_dict):
        args_sub_group_total = len(args_group[(group_counter)].split('|'))
        if isinstance(sel_sys_dict, dict):
            if args_group_count == (group_counter + 1):
                sub_group_counter = 0 
                for block in args_group[(group_counter)].split('|'):
                    if block in sel_sys_dict:
                        sub_group_counter += 1
                        selection.append(' ' * (group_counter * 4) + block + ": " + (json.dumps(sel_sys_dict[block], indent=4).strip('\"')))
            else:
                padding = ' ' * ((group_counter - 1) * 4)
                group_counter += 1   
                for block in args_group[(group_counter - 1)].split('|'):
                    if block in sel_sys_dict:
                        if not isinstance(sel_sys_dict[block], dict) and not isinstance(sel_sys_dict[block], list):
                            selection.append(padding + block + ": " + (json.dumps(sel_sys_dict[block], indent=4).strip('\"')))
                        else:
                            if group_counter == 1:
                                selection.append("\n" + block + ":: ")
                                selection.append("------------------------------")
                            else:
                                selection.append(padding + block + ": ")
                            next_sys_dict = sel_sys_dict[block]
                            RedfishParse.parse_blocks(args_group_count,args_group,selection,group_counter,sub_group_counter,next_sys_dict)
    
        elif isinstance(sel_sys_dict, list):
                for i in range(0,(int(len(sel_sys_dict)))):
                    next_sys_dict = sel_sys_dict[i]
                    RedfishParse.parse_blocks(args_group_count,args_group,selection,group_counter,sub_group_counter,next_sys_dict)
        else:
            selection.append((json.dumps(sel_sys_dict, indent=4)))
    
        if (args_group_count) == (group_counter + 1) and sub_group_counter == args_sub_group_total:
            selection.append("------------------------------")
    
        return(selection)