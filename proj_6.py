#!/usr/bin/env python3
from pprint import pprint
import networkx as nx
import os
import matplotlib.pyplot as plt

cfg_file = './Lab5-1.dot'
path_graph_dir = './graph_output'
graph_files = './out'
flag = False
cfg = nx.DiGraph()
with open(cfg_file, 'r') as cfg_file1:
    item = [line.strip('\n') for line in cfg_file1.readlines()]
prev = None
for element in item:
    if '\"' not in element:
        continue
    n1 = element.split('"')[1]
    n2 = element.split('"')[3]
    cfg.add_edge(n1, n2)
for node in list(cfg.nodes):
    if len(list(cfg.predecessors(node))) == 0:
        start = node
        print(f'START: {node}')
    if len(list(cfg.successors(node))) == 0:
        end = node
        print(f'END: {node}')

cfg_rev_nx = cfg.reverse(copy=True)
num_nodes = len(list(cfg_rev_nx.nodes))
for node in cfg_rev_nx.nodes:
    successors = set()
    sd = nx.dfs_successors(cfg_rev_nx, node)
    for k in sd:
        successors |= set(sd[k])
    if len(successors) == num_nodes-1:
        end = node
        break
end
def nodes_between(G, a, b):
    paths_between_generator = nx.all_simple_paths(G,source=a,target=b)
    nodes_between_set = {node for path in paths_between_generator for node in path}
    return nodes_between_set
if flag:
    nx.draw_circular(cfg, with_labels = True)
    plt.title("CFG")
    plt.show()
    plt.close()

cfg.add_edge('N0', start)
cfg.add_edge('N0', end)

cfg_rev_nx = cfg.reverse(copy=True)
pdom = nx.immediate_dominators(cfg_rev_nx, end)
pdom_nx = nx.DiGraph()
for n1 in pdom:
    if pdom[n1] != n1:
        pdom_nx.add_edge(pdom[n1], n1)
if flag:
    nx.draw_circular(pdom_nx, with_labels = True)
    plt.title("pdom")
    plt.show()
    plt.close()
nx.is_directed_acyclic_graph(pdom_nx)

S = set()
for A in list(cfg.nodes):
    successors = set(cfg.successors(A))
    ancestors = nx.algorithms.dag.ancestors(pdom_nx, A)
    # cond 1)
    if len(successors) >= 2:
        for B in successors:
            # cond 2)
            if B not in ancestors:
                S.add(tuple([A, B]))
cdg = nx.DiGraph()
for (A,B) in S:
    L = nx.algorithms.lowest_common_ancestors.lowest_common_ancestor(pdom_nx, A,B)
    B_to_L_nodes = nodes_between(pdom_nx, L, B)
    if L == A:
        B_to_L_nodes.add(L)
    else:
        B_to_L_nodes.remove(L)
    #print(f"({A}, {B}), L: {L}")
    #print(B_to_L_nodes)
    for dependent in B_to_L_nodes:
        cdg.add_edge(A, dependent)
if flag:
    nx.draw_circular(cdg, with_labels = True)
    plt.title(f"CDG")
    plt.show()
    plt.close()

with open('output.dot', 'w') as output_file:
    output_file.write("digraph cdg{\n")
    for (n1, n2) in cdg.edges:
        n1 = n1 if n1 != 'N0' else 'START'
        n2 = n2 if n2 != 'N0' else 'START'
        output_file.write(f"  \"{n1}\" -> \"{n2}\";\n")
    output_file.write("}\n")
len(cdg.edges)
print(list(cdg.successors('N0')))
list(cdg.successors('0x402b37'))
list(cdg.predecessors('0x402b37'))
print(list(cdg.predecessors(start)))
list(cfg.successors('0x402ab0'))
ddg_nodes = dict()
ddg_edges = dict()
for graph in graph_files:
    if ".txt" not in graph:
        continue
    nodes = True
    with open(graph, 'r') as f:
        lines = [line.strip('\n') for line in f.readlines()]
    for item in lines:
        if item == '':
            nodes = False
            continue
        item_1, item_2 = line.split('\t')[0], line.split('\t')[1]
        if nodes:
            if item_1 not in ddg_nodes:
                ddg_nodes[item_1] = item_2
                ddg_edges[item_1] = set()

        else:
            if item_1 in ddg_nodes:
                ddg_edges[item_1].add(item_2)

ddg_edges
ddg_nodes
