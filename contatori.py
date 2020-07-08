from string import *

name_count=[]
name_count_n=[]

with open('/home/gian/Desktop/Pass/access.log') as f:
    for line in f:
        list=line.split(' ',10)
        del list[9:]
        for x in range(9):
            list[x]=list[x].strip('\'u,\n').rstrip()
        if list[4]!='0' and list[4]!='None':
            try:
                index_name=name_count.index(list[4],0,len(name_count))
            except:
                index_name=-1
            if index_name!=-1:
                name_count[index_name+1]=str(int(name_count[index_name+1])+int(list[7]))
                name_count[index_name+2]=str(int(name_count[index_name+2])+int(list[8]))
            else:
                name_count.extend([list[4],int(list[7]),int(list[8])])
        if list[4]=='0':
            try:
                index_name=name_count_n.index(list[5],0,len(name_count))
            except:
                index_name=-1
            if index_name!=-1:
                name_count[index_name+1]=str(int(name_count[index_name+1])+int(list[7]))
                name_count[index_name+2]=str(int(name_count[index_name+2])+int(list[8]))
            else:
                name_count.extend([list[5],int(list[7]),int(list[8])])
print name_count

