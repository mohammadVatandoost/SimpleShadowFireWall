# This is a sample Python script.
from networkx.algorithms import isomorphism
import csv
import networkx as nx
from os import listdir
from os.path import isfile, join
import matplotlib.pyplot as plt

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.



###constants
kmax_threshold=30;
edit_distance_threshold=60

node_counter = 0
nodes = {}


def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


def make_TDG(csvFile):
    tdg = nx.DiGraph()
    global node_counter
    with open(csvFile, newline='') as csvfile:
        reader = csv.reader(csvfile, delimiter=' ', quotechar='|')
        i = 0
        for row in reader:
            # skip header row
            if i == 0:
                i = i +1
                continue
            element = row[0].split(",")
            if(len(element)<14):
                continue;
            if not (element[12] in nodes):
                nodes[element[12]] = node_counter
                tdg.add_node(node_counter)
                node_counter = node_counter + 1

            if not (element[13] in nodes):
                nodes[element[13]] = node_counter
                tdg.add_node(node_counter)
                node_counter = node_counter + 1

            tdg.add_edge(nodes[element[12]], nodes[element[13]])

    return tdg


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    trafficPath = "./Traffic-Data/"
    attackPath = "./Attack-Data/"
    attacks=[]
    #nx.draw(traffic_tdg,  edge_color='r')
    #plt.show()
    prev_traffic_tdg=None
    traffic_tdg=None
    trafficData = [f for f in listdir(trafficPath) if isfile(join(trafficPath, f))]
    for trafficFile in trafficData:
        print("--------------------"+trafficFile+"-------------------------")
        prev_traffic_tdg=traffic_tdg
        traffic_tdg = make_TDG(trafficPath+trafficFile)
        nx.draw(traffic_tdg,  edge_color='r',)# title=str(trafficFile))
        plt.show()
       
        #####Checking kmax(max degree)
        print("Cheking Kmax:")
        node_degree_list=traffic_tdg.degree()
        kmax=0
        for item in node_degree_list:
            kmax=max(item[1],kmax)
        if(kmax>kmax_threshold):
            print("----->Anomaly Detected based on kmax")
            attacks.append("Kmax")

        #####Checking Edit Distance
        print("Checking Edit Distance:")
        if(prev_traffic_tdg):
            for v in nx.optimize_graph_edit_distance(prev_traffic_tdg,traffic_tdg) :
                minv=v
                break;
            if(minv>edit_distance_threshold):
                print("----->Anomaly Detected based on edit_distance")
                attacks.append("Edit Distance")
        
        #####Checking Isomorphism
        print("Checking Isomorphism:")
        attackData = [f for f in listdir(attackPath) if isfile(join(attackPath, f))]
        for attackFile in attackData:
            attack_tdg = make_TDG(attackPath+attackFile)
            check_attack = isomorphism.DiGraphMatcher(attack_tdg, traffic_tdg)
            if(check_attack.is_isomorphic()):
                print("----->Attack Detected based on isomorphism with ", attackFile);
                attacks.append(attackFile);
    
    print("***************************result**************************")
    print("#"+str(len(attacks))+" attack(S) Detected in the traffic files!")
    print("List of attacks:")
    print(attacks)



# See PyCharm help at https://www.jetbrains.com/help/pycharm/
