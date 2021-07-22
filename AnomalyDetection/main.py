# This is a sample Python script.
from networkx.algorithms import isomorphism
import csv
import networkx as nx
from os import listdir
from os.path import isfile, join
import matplotlib.pyplot as plt

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

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
    print_hi('PyCharm')
    trafficPath = "./Traffic-Data/"
    attackPath = "./Attack-Data/"
    attacks=[]
    #nx.draw(traffic_tdg,  edge_color='r')
    #plt.show()

    trafficData = [f for f in listdir(trafficPath) if isfile(join(trafficPath, f))]
    for trafficFile in trafficData:
        traffic_tdg = make_TDG(trafficPath+trafficFile)
        nx.draw(traffic_tdg,  edge_color='r',)# title=str(trafficFile))
        plt.show()
        
        attackData = [f for f in listdir(attackPath) if isfile(join(attackPath, f))]
        for attackFile in attackData:
            print("Cheking Attack file:", attackFile)
            attack_tdg = make_TDG(attackPath+attackFile)
            check_attack = isomorphism.DiGraphMatcher(attack_tdg, traffic_tdg)
            if(check_attack.is_isomorphic()):
                print("     Attack Detected");
                attacks.append(attackPath);
            else:
                print("     No Attack");
    print("#"+str(len(attacks))+" attack(S) Detected in the traffic files!")
    print(attacks)



# See PyCharm help at https://www.jetbrains.com/help/pycharm/
