import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Page config
st.set_page_config(page_title="Threat Detection System", layout="wide")

# Title
st.title("Log Analysis & Threat Detection System")
st.markdown("Real-time monitoring of suspicious login activity")

# Load data
df = pd.read_csv('data/server_logs.csv')
df['timestamp'] = pd.to_datetime(df['timestamp'])
report = pd.read_csv('reports/suspicious_ips.csv')

# Top metrics
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Log Entries", len(df))
col2.metric("Failed Attempts", len(df[df['status'] == 'FAILED']))
col3.metric("Successful Logins", len(df[df['status'] == 'SUCCESS']))
col4.metric("High Threat IPs", len(report))

st.divider()

# Chart 1 - Failed logins by IP
st.subheader("Top 15 IPs with Most Failed Logins")
failed = df[df['status'] == 'FAILED']
failed_by_ip = failed.groupby('ip_address').size().reset_index(name='failed_attempts')
failed_by_ip = failed_by_ip.sort_values('failed_attempts', ascending=False).head(15)

fig1, ax1 = plt.subplots(figsize=(10, 5))
sns.barplot(data=failed_by_ip, x='failed_attempts', y='ip_address',
            hue='ip_address', palette='Reds_r', legend=False, ax=ax1)
ax1.set_title('Failed Login Attempts by IP')
st.pyplot(fig1)

st.divider()

# Chart 2 - Over time
st.subheader("Failed Logins Over Time")
failed_time = failed.copy()
failed_time['date'] = failed_time['timestamp'].dt.date
daily = failed_time.groupby('date').size()

fig2, ax2 = plt.subplots(figsize=(10, 4))
daily.plot(kind='line', color='red', linewidth=2, ax=ax2)
ax2.set_title('Daily Failed Login Attempts')
st.pyplot(fig2)

st.divider()

# Chart 3 - Targeted usernames
st.subheader("Most Targeted Usernames")
failed_users = failed.groupby('username').size().reset_index(name='attempts')
failed_users = failed_users.sort_values('attempts', ascending=False)

fig3, ax3 = plt.subplots(figsize=(8, 4))
sns.barplot(data=failed_users, x='username', y='attempts',
            hue='username', palette='OrRd', legend=False, ax=ax3)
st.pyplot(fig3)

st.divider()

# Suspicious IPs table
st.subheader("High Threat IP Report")
st.dataframe(report, use_container_width=True)