#!/usr/bin/python3
import numpy as np          
import pandas as pd
import matplotlib.pyplot as plt
import os
import sys
def draw_pic(fname):
	#plt.plot(xq, yq, "g-", label="Before TLB is flushed")
	#plt.plot(xq, yq, "g-")
	#plt.hist(yq, bins = 90, normed=1, color = 'r',alpha=0.5)
	#plt.xticks(range(100,500,50))
	return

if __name__ == '__main__':
	
	length = len(sys.argv) - 1
	for i in range(length):
		fname = sys.argv[i+1]
		print (fname)
		
		iq_data = pd.read_csv(fname)
		xq = iq_data['index']
		yq = iq_data['timing']
		std = yq.std()	
		print ("std:%f" % std)		
		plt.plot(xq, yq, "g-")
		name = fname[0:fname.index('.')]
		figname = name + ".pdf"
		plt.savefig(figname)
		plt.cla()
		plt.xlabel('index')
		plt.ylabel('distribution')
		os.system("evince " + figname + " &")

