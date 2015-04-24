import plotly.plotly as py
from plotly.graph_objs import *
import time, random

#data is a list of diameter data
def findAverageDiameter(data):
    sum = 0
    count = 0
    #sum all of the values in vals
    for value in data:
        sum = sum + value
        count = count + 1
    #divide by # of values in vals
    average = sum / count
    print('Average Throughput =' , average, 'bits/sec')
    
    return average

#diameter is the list of diameter valuess
def findMaxDiameter(diameter):
    maxDiameter = max(diameter)
    print('Max Diameter =', maxDiameter)
    return maxDiameter

#tp is a list of throughputs
def plotThroughputData(tp):
    plotType = 'markers+lines'
    sec = []
    for i in range(0,len(tp)):
        sec.append(i)#sec[i] = i
        i+=1
    throughputData = Scatter(x=sec,
                     y=tp,
                     mode=plotType)

    data = Data([throughputData])
    plot_url = py.plot(data,filename='Average Throughput')

def findAverageThroughput(vals):
    sum = 0
    count = 0
    #sum all of the values in vals
    for value in vals:
        sum = sum + value
        count = count + 1
    #divide by # of values in vals
    average = sum / count
    print('Average Throughput =' , average, 'bits/sec')
    
    return average

def plotCongestionWindowData(congestionY):
    plotType = 'markers+lines'
    sec = []
    congestionX = []
    for i in range(0,len(congestionY)):
        congestionX.append(i)
        i+=1
    throughputData = Scatter(x=congestionX,
                     y=congestionY,
                     mode=plotType)

    data = Data([throughputData])
    plot_url = py.plot(data,filename='Congestion Window')

def findAveragePacketFrameSize(vals):
    sum = 0
    count = 0
    #sum all of the values in vals
    for value in vals:
        sum = sum + value
        count = count + 1
    #divide by # of values in vals
    average = sum / count
    print('Average Packet/Frame Size =' , average, 'bits')

    return average
'''
def main():

    
    x = [random.randint(0,500),random.randint(0,500),random.randint(0,500),
         random.randint(0,500),random.randint(0,500),random.randint(0,500),
         random.randint(0,500),random.randint(0,500),random.randint(0,500)]

    findMaxDiameter(x)
    plotThroughputData(x)
    findAveragePacketFrameSize(x)
    plotCongestionWindowData(x)



main()
'''
