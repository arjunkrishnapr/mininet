class Simhost(object):
    simhost_nodes=[]
    def __init__(self, node):
        Simhost.simhost_nodes.append(node)
        print('Simhost node added')

