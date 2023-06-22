import pandas as pd
import numpy as np
import plotly.express as px
import time
from sklearn.metrics import classification_report, confusion_matrix
pd.options.mode.chained_assignment = None  # default='warn'
#读取数据
# 指定文件路径
# file_path = './data/portv3.csv'
# file_path = './data/new_portv3_p75.csv'
file_path = 'new_portv3_p50.csv'
# read csv file
# 从csv文件中读取csv数据
data_raw = pd.read_csv(file_path)
true_attack = pd.read_csv('port-ver3-packets.csv', usecols=['Interval start', 'Attack'])
#整理数据
# drop unnecessary columns
# 忽略不用的列
data = data_raw.copy()

if ['No.', 'Protocol', 'info', 'Source', 'Destination Port'] in list(data.columns):
    data = data.drop(['No.', 'Protocol', 'info', 'Source', 'Destination Port'], axis=1)
    
data['Source Port'] = data['Source Port'].fillna(0)

# ignore negative time
# 忽略负数时间，保留time >= 0s的数据
# '~'表示取反，即不取'Time'小于0的数据
data = data[~(data['Time'] < 0)]


# 拿到整个数据中最大的秒数并向上取整
# get the largest time from the data, e.g. 75.370354
max_time = np.max(data['Time'])
# round up the number, e.g. 76
max_time = int(np.ceil(max_time))
max_time
150
# 按每秒切分数据为一组
time_range = pd.cut(data['Time'],                       # 指定是time这一列
                    np.arange(0, max_time+1, 1),        # 指定划分的区间，e.g. [0,76]这个区间，以1s为间隔划分
                    right=False,                        # 每个区间不包含右边, e.g. [0,1)
                    labels=np.arange(1, max_time+1, 1)  # 指定每个区间的标签，这里即使第几秒, e.g. [0,1) -> 1s
                   )
# 将每一行数据划分到这个区间
data['Second'] = time_range

data['Second'] = data.Second.cat.codes + 1

# # 指定每秒取前多少个packet
# # 如果实际每秒没有这么多packet，这里不会报错的
# top_n = 100

# # 每个区间(即每秒)取前top_n个packet
# # 因此原本整个数据有27779行，现在只剩3796行
# data = data.groupby('Second').head(top_n).reset_index(drop=True)
# data
# 指定每秒随机取多少个packet
# 如果实际每秒没有这么多packet，这里不会报错的
random_n = 100

# 每个区间(即每秒)随机取packet
# 因此原本整个数据有27779行，现在只剩3796行


data = data.groupby('Second').apply(lambda x: x.sample(min(random_n, len(x)))).reset_index(drop=True)
print(data)
source_statistics = data[['Second', 'Source Port', 'Time']].groupby(['Second', 'Source Port']).count().rename(columns={'Time': 'count'})
source_statistics = source_statistics.reset_index()
# remove zero count rows
source_statistics = source_statistics[source_statistics['count'] != 0].reset_index(drop=True)

# 查询source ip第几秒的数据
query_second = 1
source_statistics[source_statistics['Second'] == query_second]

destination_statistics = data[['Second', 'Destination', 'Time']].groupby(['Second', 'Destination']).count().rename(columns={'Time': 'count'})
destination_statistics = destination_statistics.reset_index()
# remove zero count rows
destination_statistics = destination_statistics[destination_statistics['count'] != 0].reset_index(drop=True)


# 查询destination ip第几秒的数据
query_second = 1
destination_statistics[destination_statistics['Second'] == query_second]

packet_len_statistics = data[['Second', 'Length', 'Time']].groupby(['Second', 'Length']).count().rename(columns={'Time': 'count'})
packet_len_statistics = packet_len_statistics.reset_index()
# remove zero count rows
packet_len_statistics = packet_len_statistics[packet_len_statistics['count'] != 0].reset_index(drop=True)


# 查询packet length第几秒的数据
query_second = 1
packet_len_statistics[packet_len_statistics['Second'] == query_second]

# # 保存统计数据为一个多页的excel
# # Create a Pandas Excel writer using XlsxWriter as the engine.
# excel_writer = pd.ExcelWriter('statistics.xlsx', engine='xlsxwriter')

# # Write each dataframe to a different worksheet.
# source_statistics.to_excel(excel_writer, sheet_name='source')
# destination_statistics.to_excel(excel_writer, sheet_name='destination')
# packet_len_statistics.to_excel(excel_writer, sheet_name='packet_length')

# # Close the Pandas Excel writer and output the Excel file.
# excel_writer.save()
#计算destination的单熵
destination_temp = destination_statistics.groupby(['Second', 'Destination']).sum().rename(columns={'count': 'p'})
# remove zero count rows
destination_temp = destination_temp[destination_temp['p'] != 0]
# 计算概率p
destination_temp = destination_temp.groupby(level=0).apply(lambda x: x / x.sum())
destination_temp = destination_temp.reset_index(level=1, drop=True)
# 计算log(p)

destination_temp['log_p'] = destination_temp.groupby(level=0,axis=1).apply(lambda x: np.log2(x))
# 计算乘积
destination_temp['multiply'] = round(destination_temp['p'] * destination_temp['log_p'], 4)

# 把每个组的乘积加起来即为单熵
destination_entropy = destination_temp[['multiply']].groupby(level=0).sum()
destination_entropy = destination_entropy.reset_index()
# 取负数
destination_entropy['multiply'] = destination_entropy['multiply'] * -1

#计算destination之于source port的条件熵
# 拿到上面计算的destination的概率
dest_p = destination_temp
dest_p = destination_temp.reset_index()
# 忽略掉不要的列
dest_p = dest_p.drop(['log_p', 'multiply'], axis=1)

dest_src_temp = data[['Second','Source Port','Destination','Time']].groupby(['Second','Destination','Source Port']).count().rename(columns={'Time': 'count'})
# remove zero count rows
dest_src_temp = dest_src_temp[dest_src_temp['count'] != 0]
# 统计相同destination的情况下，有多少个source
dest_src_temp = dest_src_temp.groupby(['Second','Destination']).apply(lambda grp: grp.groupby('Source Port').sum())
# 计算destination之于source的条件概率condition_p
dest_src_temp['condition_p'] = dest_src_temp.groupby(['Second','Destination']).apply(lambda grp: grp.groupby('Source Port').sum() / grp.sum())
# 计算log(condition_p)
dest_src_temp['log_condition_p'] = np.log2(dest_src_temp['condition_p'])
# 计算乘积
dest_src_temp['p_multiply'] = round(dest_src_temp['condition_p'] * dest_src_temp['log_condition_p'], 4)

dest_src_entropy = dest_src_temp
dest_src_entropy['p_sum'] = dest_src_entropy['p_multiply'].groupby(['Second','Destination']).sum()
dest_src_entropy = dest_src_entropy.reset_index()
dest_src_entropy = dest_src_entropy.drop(['count'], axis=1)
#print(dest_src_entropy)

# 将destination的概率和条件概率两个dataframe合并
dest_src_entropy = pd.merge(dest_src_entropy, dest_p, on=['Second','Destination'], how='left')
#print(dest_src_entropy)
# 将两个概率相乘
dest_src_entropy['total_multiply'] = round(dest_src_entropy['p_sum'] * dest_src_entropy['p'], 4)

dest_src_entropy = dest_src_entropy[['Second','Destination','total_multiply']]
# 扔掉重复行
dest_src_entropy = dest_src_entropy.drop_duplicates()
#print(dest_src_entropy)

# 把每个组的乘积加起来即为单熵
dest_src_entropy = dest_src_entropy[['Second','total_multiply']].groupby(['Second']).sum()
dest_src_entropy = dest_src_entropy.reset_index()
# 取负数
dest_src_entropy['total_multiply'] = dest_src_entropy['total_multiply'].apply(lambda x: -1*x if x != 0 else x)

dest_len_temp = data[['Second','Length','Destination','Time']].groupby(['Second','Destination','Length']).count().rename(columns={'Time': 'count'})
# remove zero count rows
dest_len_temp = dest_len_temp[dest_len_temp['count'] != 0]
# 统计相同destination的情况下，有多少个source
dest_len_temp = dest_len_temp.groupby(['Second','Destination']).apply(lambda grp: grp.groupby('Length').sum())
# 计算destination之于source的条件概率condition_p
dest_len_temp['condition_p'] = dest_len_temp.groupby(['Second','Destination']).apply(lambda grp: grp.groupby('Length').sum() / grp.sum())
# 计算log(condition_p)
dest_len_temp['log_condition_p'] = np.log2(dest_len_temp['condition_p'])
# 计算乘积
dest_len_temp['p_multiply'] = round(dest_len_temp['condition_p'] * dest_len_temp['log_condition_p'], 4)
dest_len_temp.to_excel('len.xlsx')

# 把每个组的乘积加起来
dest_len_entropy = dest_len_temp
dest_len_entropy['p_sum'] = dest_len_entropy['p_multiply'].groupby(['Second','Destination']).sum()
dest_len_entropy = dest_len_entropy.reset_index()
dest_len_entropy = dest_len_entropy.drop(['count'], axis=1)
#print(dest_len_entropy)

# 将destination的概率和条件概率两个dataframe合并
dest_len_entropy = pd.merge(dest_len_entropy, dest_p, on=['Second','Destination'], how='left')
# 将两个概率相乘
dest_len_entropy['total_multiply'] = round(dest_len_entropy['p_sum'] * dest_len_entropy['p'], 4)

dest_len_entropy = dest_len_entropy[['Second','Destination','total_multiply']]
# 扔掉重复行
dest_len_entropy = dest_len_entropy.drop_duplicates()
#print(dest_len_entropy)

# 把每个组的乘积加起来即为单熵
dest_len_entropy = dest_len_entropy[['Second','total_multiply']].groupby(['Second']).sum()
dest_len_entropy = dest_len_entropy.reset_index()
# 取负数
dest_len_entropy['total_multiply'] = dest_len_entropy['total_multiply'].apply(lambda x: -1*x if x != 0 else x)
#print(dest_len_entropy)

destination_entropy1 = destination_entropy.copy()
first_10_avg = destination_entropy1['multiply'][:10].sum() / 10
destination_entropy1['old_attack_m1'] = np.where(destination_entropy1['multiply'] < first_10_avg, 0, 1)
destination_entropy1['old_attack_m1'].loc[:9] = -1

destination_entropy2 = destination_entropy.copy()
destination_entropy2['cum_sum'] = destination_entropy2['multiply'].cumsum()
destination_entropy2['avg_entropy'] = destination_entropy2['cum_sum'] / destination_entropy2['Second']
destination_entropy2['old_attack_m2'] = np.where(destination_entropy2['multiply'] < destination_entropy2['avg_entropy'], 0, 1)
destination_entropy2['old_attack_m2'].loc[:9] = -1

tqv_dest_entropy_m1 = destination_entropy.copy()
tqv_dest_src_entropy_m1 = dest_src_entropy.copy()
tqv_dest_len_entropy_m1 = dest_len_entropy.copy()
tqv_dest_first_10_avg = tqv_dest_entropy_m1['multiply'][:10].sum() / 10
tqv_dest_entropy_m1['dest_attack'] = np.where(tqv_dest_entropy_m1['multiply'] < tqv_dest_first_10_avg, 0, 1)
tqv_dest_entropy_m1['dest_attack'].loc[:9] = -1

tqv_dest_src_first_10_avg = tqv_dest_src_entropy_m1['total_multiply'][:10].sum() / 10
tqv_dest_src_entropy_m1['dest_src_attack'] = np.where(tqv_dest_src_entropy_m1['total_multiply'] < tqv_dest_src_first_10_avg, 0, 1)
tqv_dest_src_entropy_m1['dest_src_attack'].loc[:9] = -1

tqv_dest_len_first_10_avg = tqv_dest_len_entropy_m1['total_multiply'][:10].sum() / 10
tqv_dest_len_entropy_m1['dest_len_attack'] = np.where(tqv_dest_len_entropy_m1['total_multiply'] < tqv_dest_len_first_10_avg, 0, 1)
tqv_dest_len_entropy_m1['dest_len_attack'].loc[:9] = -1

tqv_method1 = tqv_dest_entropy_m1[['Second','dest_attack']].merge(tqv_dest_src_entropy_m1[['Second','dest_src_attack']], on='Second')
tqv_method1 = tqv_method1.merge(tqv_dest_len_entropy_m1[['Second','dest_len_attack']], on='Second')

def tqv_attack_logic(row):
    if row['dest_attack'] == 1:
        return 1
    elif row['dest_attack'] == 0 and row['dest_src_attack'] == 1 and row['dest_len_attack'] == 1:
        return 1
    elif row['dest_attack'] == 0 and row['dest_src_attack'] == 0 and row['dest_len_attack'] == 0 :
        return 0
    elif row['dest_attack'] == 0 and row['dest_src_attack'] == 1 and row['dest_len_attack'] == 0:
        return 0
    elif row['dest_attack'] == 0 and row['dest_src_attack'] == 0 and row['dest_len_attack'] == 1:
        return 1
    else:
        # when encounters the first 10 rows
        return -1
tqv_method1['tqv_attack_m1'] = tqv_method1.apply(lambda row: tqv_attack_logic(row), axis=1)


tqv_dest_entropy_m2 = destination_entropy.copy()
tqv_dest_src_entropy_m2 = dest_src_entropy.copy()
tqv_dest_len_entropy_m2 = dest_len_entropy.copy()
tqv_dest_entropy_m2['cum_sum'] = tqv_dest_entropy_m2['multiply'].cumsum()
tqv_dest_entropy_m2['avg_entropy'] = tqv_dest_entropy_m2['cum_sum'] / tqv_dest_entropy_m2['Second']
tqv_dest_entropy_m2['dest_attack'] = np.where(tqv_dest_entropy_m2['multiply'] < tqv_dest_entropy_m2['avg_entropy'], 0, 1)
tqv_dest_entropy_m2['dest_attack'].loc[:9] = -1

tqv_dest_src_entropy_m2['cum_sum'] = tqv_dest_src_entropy_m2['total_multiply'].cumsum()
tqv_dest_src_entropy_m2['avg_entropy'] = tqv_dest_src_entropy_m2['cum_sum'] / tqv_dest_src_entropy_m2['Second']
tqv_dest_src_entropy_m2['dest_src_attack'] = np.where(tqv_dest_src_entropy_m2['total_multiply'] < tqv_dest_src_entropy_m2['avg_entropy'], 0, 1)
tqv_dest_src_entropy_m2['dest_src_attack'].loc[:9] = -1

tqv_dest_len_entropy_m2['cum_sum'] = tqv_dest_len_entropy_m2['total_multiply'].cumsum()
tqv_dest_len_entropy_m2['avg_entropy'] = tqv_dest_len_entropy_m2['cum_sum'] / tqv_dest_len_entropy_m2['Second']
tqv_dest_len_entropy_m2['dest_len_attack'] = np.where(tqv_dest_len_entropy_m2['total_multiply'] < tqv_dest_len_entropy_m2['avg_entropy'], 0, 1)
tqv_dest_len_entropy_m2['dest_len_attack'].loc[:9] = -1


tqv_method2 = tqv_dest_entropy_m2[['Second','dest_attack']].merge(tqv_dest_src_entropy_m2[['Second','dest_src_attack']], on='Second')
tqv_method2 = tqv_method2.merge(tqv_dest_len_entropy_m2[['Second','dest_len_attack']], on='Second')

tqv_method2['tqv_attack_m2'] = tqv_method2.apply(lambda row: tqv_attack_logic(row), axis=1)

tqv_dest_entropy_m3 = destination_entropy.copy()
tqv_dest_src_entropy_m3 = dest_src_entropy.copy()
tqv_dest_len_entropy_m3 = dest_len_entropy.copy()


def check_attack(row, key, lower_, higher_):
    if row[key] >= lower_ and row[key] <= higher_:
        return 2
    elif row[key] < lower_:
        return 0
    elif row[key] > higher_:
        return 1
    
tqv_dest_entropy_m3.to_excel('values.xlsx')
tqv_dest_src_entropy_m3.to_excel('values2.xlsx')
tqv_dest_len_entropy_m3.to_excel('values3.xlsx')


tqv_dest_entropy_m3['cum_sum'] = tqv_dest_entropy_m3['multiply'].cumsum()
tqv_dest_entropy_m3['avg_entropy'] = tqv_dest_entropy_m3['cum_sum'] / tqv_dest_entropy_m3['Second']

dest_lower_ = tqv_dest_entropy_m3['avg_entropy'][9] - 2 * np.std(tqv_dest_entropy_m3['multiply'][:10])
dest_higher_ = tqv_dest_entropy_m3['avg_entropy'][9] + 2 * np.std(tqv_dest_entropy_m3['multiply'][:10])
print(dest_lower_,dest_higher_)

tqv_dest_entropy_m3['dest_attack'] = tqv_dest_entropy_m3.apply(lambda row: check_attack(row, 'multiply', dest_lower_, dest_higher_), axis=1)
tqv_dest_entropy_m3['dest_attack'].loc[:9] = -1

tqv_dest_src_entropy_m3['cum_sum'] = tqv_dest_src_entropy_m3['total_multiply'].cumsum()
tqv_dest_src_entropy_m3['avg_entropy'] = tqv_dest_src_entropy_m3['cum_sum'] / tqv_dest_src_entropy_m3['Second']


dest_src_lower_ = tqv_dest_src_entropy_m3['avg_entropy'][9] - 2 * np.std(tqv_dest_src_entropy_m3['total_multiply'][:10])
dest_src_higher_ = tqv_dest_src_entropy_m3['avg_entropy'][9] + 2 * np.std(tqv_dest_src_entropy_m3['total_multiply'][:10])
print(dest_src_lower_,dest_src_higher_)

tqv_dest_src_entropy_m3['dest_src_attack'] = tqv_dest_src_entropy_m3.apply(lambda row: check_attack(row, 'total_multiply',dest_src_lower_,dest_src_higher_), axis=1)
tqv_dest_src_entropy_m3['dest_src_attack'].loc[:9] = -1

tqv_dest_len_entropy_m3['cum_sum'] = tqv_dest_len_entropy_m3['total_multiply'].cumsum()
tqv_dest_len_entropy_m3['avg_entropy'] = tqv_dest_len_entropy_m3['cum_sum'] / tqv_dest_len_entropy_m3['Second']


dest_len_lower_ = tqv_dest_len_entropy_m3['avg_entropy'][9] - 2 * np.std(tqv_dest_len_entropy_m3['total_multiply'][:10])
dest_len_higher_ = tqv_dest_len_entropy_m3['avg_entropy'][9] + 2 * np.std(tqv_dest_len_entropy_m3['total_multiply'][:10])
print(dest_len_lower_,dest_len_higher_)

tqv_dest_len_entropy_m3['dest_len_attack'] = tqv_dest_len_entropy_m3.apply(lambda row: check_attack(row, 'total_multiply',dest_len_lower_,dest_len_higher_), axis=1)
tqv_dest_len_entropy_m3['dest_len_attack'].loc[:9] = -1

tqv_method3 = tqv_dest_entropy_m3[['Second','dest_attack']].merge(tqv_dest_src_entropy_m3[['Second','dest_src_attack']], on='Second')
tqv_method3 = tqv_method3.merge(tqv_dest_len_entropy_m3[['Second','dest_len_attack']], on='Second')


def new_tqv_attack_logic(row):
    if row['dest_attack'] == 1:
        return 1
    elif row['dest_attack'] == 2:
        return 1
    elif row['dest_attack'] == 0:
        if row['dest_src_attack'] == 1 and row['dest_len_attack'] == 1:
            return 1
        elif row['dest_src_attack'] == 0 and row['dest_len_attack'] == 0:
            return 0
        elif row['dest_src_attack'] == 1 and row['dest_len_attack'] == 0:
            return 0
        else:
            return 0
    else:
        return -1

    
tqv_method3['tqv_attack_m3'] = tqv_method3.apply(lambda row: new_tqv_attack_logic(row), axis=1)


true_attack = true_attack.iloc[1:].reset_index(drop=True)
true_attack = true_attack.rename(columns={'Interval start': 'Second', 'Attack': 'true_attack'})
true_attack['true_attack'] = true_attack['true_attack'].replace('-', -1)
true_attack['true_attack'] = true_attack['true_attack'].astype(int)

attack_compare = true_attack.merge(destination_entropy1[['Second','old_attack_m1']], on='Second')
attack_compare = attack_compare.merge(destination_entropy2[['Second','old_attack_m2']], on='Second')
attack_compare = attack_compare.merge(tqv_method1[['Second','tqv_attack_m1']], on='Second')
attack_compare = attack_compare.merge(tqv_method2[['Second','tqv_attack_m2']], on='Second')
attack_compare = attack_compare.merge(tqv_method3[['Second','tqv_attack_m3']], on='Second')


attack_compare = attack_compare.iloc[9:]
attack_compare[:20]


def metrics(attack_compare, predicted_label, true_label='true_attack'):
    print(f'================== The metrics of {predicted_label} ==================')
    print(classification_report(attack_compare[true_label], attack_compare[predicted_label]))
    print()

metrics(attack_compare, 'old_attack_m1')
metrics(attack_compare, 'old_attack_m2')
metrics(attack_compare, 'tqv_attack_m1')
metrics(attack_compare, 'tqv_attack_m2')
metrics(attack_compare, 'tqv_attack_m3')



def f1(attack_compare, predicted_label, true_label='true_attack'):
    print(f'==== The metrics of {predicted_label} ====')
    print(confusion_matrix(attack_compare[true_label], attack_compare[predicted_label]))
    print()

f1(attack_compare, 'old_attack_m1')
f1(attack_compare, 'old_attack_m2')
f1(attack_compare, 'tqv_attack_m1')
f1(attack_compare, 'tqv_attack_m2')
f1(attack_compare, 'tqv_attack_m3')

tqv_method3.to_excel('error.xlsx')
#print(tqv_method3)
#print(attack_compare)

fig = px.line(destination_entropy,
              x='Second', 
              y="multiply",
              title="Entropy of Destination"
             )
# fig.update_xaxes(range = [-4,4])
fig.update_yaxes(title='Entropy')
fig.show()

fig = px.line(dest_src_entropy,
              x='Second', 
              y="total_multiply",
              title="Entropy of Destination conditioned on Source Port"
             )
# fig.update_xaxes(rangemode='tozero')
fig.update_yaxes(title='Entropy')
fig.show()

fig = px.line(dest_len_entropy,
              x='Second', 
              y="total_multiply",
              title="Entropy of Destination conditioned on Packet Length"
             )
# fig.update_xaxes(range = [-4,4])
fig.update_yaxes(title='Entropy')
fig.show()
