"""Render baseline validation and known-positive physical activation figures."""
from pathlib import Path
import os
ROOT=Path(__file__).resolve().parents[2]
os.environ.setdefault('MPLCONFIGDIR',str(ROOT/'tmp/matplotlib'))
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def main():
    out=ROOT/'results/figures'; out.mkdir(parents=True,exist_ok=True)
    base=ROOT/'results/validation'
    read=lambda part,circuit,name: np.loadtxt(base/part/circuit/f'{name}.tsv',skiprows=1)
    plt.rcParams.update({'font.size':9,'axes.spines.top':False,'axes.spines.right':False,'savefig.dpi':180})
    fig,axes=plt.subplots(1,3,figsize=(10.5,2.8),constrained_layout=True)
    d=read('clean','and4','normal'); t=(np.arange(16)+1)*20e-6+10e-6
    axes[0].plot(np.arange(16),np.interp(t,d[:,0],d[:,-1]),'o-',color='#1c6e8c')
    axes[0].set(xlabel='Input vector index (a is LSB)',ylabel='Output (V)',title='AND4: 16 truth-table cases',xticks=[0,5,10,15],ylim=(-.15,3.5))
    d=read('clean','opamp','normal'); axes[1].plot(d[:,0]*1e6,d[:,1],label='Input',color='#d9883d');axes[1].plot(d[:,0]*1e6,d[:,2],label='Output',color='#1c6e8c',linestyle='--')
    axes[1].set(xlabel='Time (us)',ylabel='Voltage (V)',title='Opamp: unity follower');axes[1].legend(fontsize=8)
    d=read('clean','opamp','ac'); h=d[:,1]+1j*d[:,2]
    axes[2].semilogx(d[:,0],20*np.log10(abs(h)),color='#1c6e8c');axes[2].axhline(0,color='grey',lw=.6)
    axes[2].set(xlabel='Frequency (Hz)',ylabel='Open-loop gain (dB)',title='Opamp: AC response',ylim=(-30,100))
    fig.savefig(out/'clean_validation.png');fig.savefig(out/'clean_validation.pdf');plt.close(fig)
    fig,axes=plt.subplots(2,2,figsize=(10,5.2),constrained_layout=True)
    for j,c in enumerate(['and4','opamp']):
        clean=read('clean',c,'trigger');attack=read('positive',c,'trigger');norm=read('positive',c,'normal')
        axes[0,j].plot(clean[:,0]*1e6,clean[:,2],label='Clean output',color='#1c6e8c',lw=1)
        axes[0,j].plot(attack[:,0]*1e6,attack[:,2],label='Modified output',color='#c55845',lw=1)
        axes[0,j].set(xlabel='Time (us)',ylabel='Output (V)',title='AND4: high-frequency burst' if c=='and4' else 'Opamp: burst and recovery',xlim=(40,43) if c=='and4' else (40,65))
        axes[0,j].legend(fontsize=8)
        axes[1,j].plot(norm[:,0]*1e6,norm[:,-1],label='Normal stimulus',color='#1c6e8c')
        axes[1,j].plot(attack[:,0]*1e6,attack[:,-1],label='Activation stimulus',color='#c55845')
        axes[1,j].axhline(.85 if c=='and4' else .4,color='grey',ls='--',lw=.8,label='Switch threshold')
        axes[1,j].set(xlabel='Time (us)',ylabel='Reservoir voltage (V)',title='RC charge accumulation',xlim=(0,55) if c=='and4' else (0,75))
        axes[1,j].legend(fontsize=8)
    fig.savefig(out/'activation_validation.png');fig.savefig(out/'activation_validation.pdf');plt.close(fig)
if __name__=='__main__': main()
