# Lynceus Telemetry Matrix — Complete Feature Dictionary (v1.0)

This document contains the exhaustive list of the 495 features extracted by the Lynceus eBPF Engine, numbered according to their export order in the CSV stream.

## Flow Identification & Metadata
1.  **flow_id**: Unique string identifier for the network flow.
2.  **src_ip**: Source IP address (IPv4/IPv6).
3.  **dst_ip**: Destination IP address (IPv4/IPv6).
4.  **src_port**: Transport layer source port.
5.  **dst_port**: Transport layer destination port.
6.  **protocol**: IP protocol number (e.g., 6=TCP, 17=UDP).
7.  **ip_ver**: IP version (4 or 6).
8.  **eth_proto**: Ethernet protocol identifier.
9.  **traffic_class**: IPv6 Traffic Class or IPv4 Type of Service (TOS).
10. **flow_label**: IPv6 Flow Label (20-bit flow identifier).
11. **src_mac**: Source MAC address.
12. **dst_mac**: Destination MAC address.
13. **timestamp**: Flow start epoch (nanoseconds).
14. **duration**: Total flow duration in nanoseconds.
15. **PacketsCount**: Total number of packets in the flow.
16. **FwdPacketsCount**: Number of packets in the forward direction.
17. **BwdPacketsCount**: Number of packets in the backward direction.
18. **TotalBytes**: Total cumulative bytes in the flow.
19. **FwdBytes**: Total bytes in the forward direction.
20. **BwdBytes**: Total bytes in the backward direction.
21. **FwdBwdPktRatio**: Ratio of forward packets to backward packets.
22. **FwdBwdByteRatio**: Ratio of forward bytes to backward bytes.

## Statistical Suite: Tot_Pay (Total Payload Size)
23. **Tot_Pay_Max**: Maximum payload size observed.
24. **Tot_Pay_Min**: Minimum payload size observed.
25. **Tot_Pay_Mean**: Mean payload size (Welford).
26. **Tot_Pay_Std**: Standard deviation of payload size.
27. **Tot_Pay_Var**: Variance of payload size.
28. **Tot_Pay_Median**: Median payload size (Histogram Interpolation).
29. **Tot_Pay_Skew**: Skewness of payload distribution.
30. **Tot_Pay_Kurt**: Kurtosis of payload distribution.
31. **Tot_Pay_CoV**: Coefficient of Variation for payload.
32. **Tot_Pay_Mode**: Statistical mode (Fallback 0.00).

## Statistical Suite: Fwd_Pay (Forward Payload Size)
33. **Fwd_Pay_Max**: Maximum forward payload size.
34. **Fwd_Pay_Min**: Minimum forward payload size.
35. **Fwd_Pay_Mean**: Mean forward payload size.
36. **Fwd_Pay_Std**: Standard deviation of forward payload.
37. **Fwd_Pay_Var**: Variance of forward payload.
38. **Fwd_Pay_Median**: Median forward payload size.
39. **Fwd_Pay_Skew**: Skewness of forward payload.
40. **Fwd_Pay_Kurt**: Kurtosis of forward payload.
41. **Fwd_Pay_CoV**: Coefficient of Variation for forward payload.
42. **Fwd_Pay_Mode**: Statistical mode for forward payload.

## Statistical Suite: Bwd_Pay (Backward Payload Size)
43. **Bwd_Pay_Max**: Maximum backward payload size.
44. **Bwd_Pay_Min**: Minimum backward payload size.
45. **Bwd_Pay_Mean**: Mean backward payload size.
46. **Bwd_Pay_Std**: Standard deviation of backward payload.
47. **Bwd_Pay_Var**: Variance of backward payload.
48. **Bwd_Pay_Median**: Median backward payload size.
49. **Bwd_Pay_Skew**: Skewness of backward payload.
50. **Bwd_Pay_Kurt**: Kurtosis of backward payload.
51. **Bwd_Pay_CoV**: Coefficient of Variation for backward payload.
52. **Bwd_Pay_Mode**: Statistical mode for backward payload.

## Statistical Suite: Tot_Hdr (Total Header Size)
53. **Tot_Hdr_Max**: Maximum header length observed (L3+L4).
54. **Tot_Hdr_Min**: Minimum header length observed.
55. **Tot_Hdr_Mean**: Mean header length.
56. **Tot_Hdr_Std**: Standard deviation of header length.
57. **Tot_Hdr_Var**: Variance of header length.
58. **Tot_Hdr_Median**: Median header length (P²).
59. **Tot_Hdr_Skew**: Skewness of header distribution.
60. **Tot_Hdr_Kurt**: Kurtosis of header distribution.
61. **Tot_Hdr_CoV**: Coefficient of Variation for headers.
62. **Tot_Hdr_Mode**: Mode of header distribution.

## Statistical Suite: Fwd_Hdr (Forward Header Size)
63. **Fwd_Hdr_Max**: Maximum forward header length.
64. **Fwd_Hdr_Min**: Minimum forward header length.
65. **Fwd_Hdr_Mean**: Mean forward header length.
66. **Fwd_Hdr_Std**: Standard deviation of forward header.
67. **Fwd_Hdr_Var**: Variance of forward header.
68. **Fwd_Hdr_Median**: Median forward header length.
69. **Fwd_Hdr_Skew**: Skewness of forward header.
70. **Fwd_Hdr_Kurt**: Kurtosis of forward header.
71. **Fwd_Hdr_CoV**: Coefficient of Variation for forward headers.
72. **Fwd_Hdr_Mode**: Mode of forward header distribution.

## Statistical Suite: Bwd_Hdr (Backward Header Size)
73. **Bwd_Hdr_Max**: Maximum backward header length.
74. **Bwd_Hdr_Min**: Minimum backward header length.
75. **Bwd_Hdr_Mean**: Mean backward header length.
76. **Bwd_Hdr_Std**: Standard deviation of backward header.
77. **Bwd_Hdr_Var**: Variance of backward header.
78. **Bwd_Hdr_Median**: Median backward header length.
79. **Bwd_Hdr_Skew**: Skewness of backward header.
80. **Bwd_Hdr_Kurt**: Kurtosis of backward header.
81. **Bwd_Hdr_CoV**: Coefficient of Variation for backward headers.
82. **Bwd_Hdr_Mode**: Mode of backward header distribution.

## Statistical Suite: Tot_IAT (Total Inter-Arrival Time)
83. **Tot_IAT_Max**: Maximum inter-arrival time in the flow (ns).
84. **Tot_IAT_Min**: Minimum inter-arrival time.
85. **Tot_IAT_Mean**: Mean inter-arrival time.
86. **Tot_IAT_Std**: Standard deviation of IAT.
87. **Tot_IAT_Var**: Variance of IAT (Jitter indicator).
88. **Tot_IAT_Median**: Median IAT (P²).
89. **Tot_IAT_Skew**: Skewness of IAT distribution.
90. **Tot_IAT_Kurt**: Kurtosis of IAT distribution.
91. **Tot_IAT_CoV**: Coefficient of Variation for IAT.
92. **Tot_IAT_Mode**: Mode of IAT distribution.

## Statistical Suite: Fwd_IAT (Forward Inter-Arrival Time)
93. **Fwd_IAT_Max**: Maximum IAT in the forward direction.
94. **Fwd_IAT_Min**: Minimum forward IAT.
95. **Fwd_IAT_Mean**: Mean forward IAT.
96. **Fwd_IAT_Std**: Standard deviation of forward IAT.
97. **Fwd_IAT_Var**: Variance of forward IAT.
98. **Fwd_IAT_Median**: Median forward IAT.
99. **Fwd_IAT_Skew**: Skewness of forward IAT.
100. **Fwd_IAT_Kurt**: Kurtosis of forward IAT.
101. **Fwd_IAT_CoV**: Coefficient of Variation for forward IAT.
102. **Fwd_IAT_Mode**: Mode of forward IAT distribution.

## Statistical Suite: Bwd_IAT (Backward Inter-Arrival Time)
103. **Bwd_IAT_Max**: Maximum IAT in the backward direction.
104. **Bwd_IAT_Min**: Minimum backward IAT.
105. **Bwd_IAT_Mean**: Mean backward IAT.
106. **Bwd_IAT_Std**: Standard deviation of backward IAT.
107. **Bwd_IAT_Var**: Variance of backward IAT.
108. **Bwd_IAT_Median**: Median backward IAT.
109. **Bwd_IAT_Skew**: Skewness of backward IAT.
110. **Bwd_IAT_Kurt**: Kurtosis of backward IAT.
111. **Bwd_IAT_CoV**: Coefficient of Variation for backward IAT.
112. **Bwd_IAT_Mode**: Mode of backward IAT distribution.

## Statistical Suite: Tot_DeltaLen (Packet Length Delta)
113. **Tot_DeltaLen_Max**: Maximum change in packet size between consecutive frames.
114. **Tot_DeltaLen_Min**: Minimum packet size delta.
115. **Tot_DeltaLen_Mean**: Mean packet size delta.
116. **Tot_DeltaLen_Std**: Standard deviation of size delta.
117. **Tot_DeltaLen_Var**: Variance of packet size delta.
118. **Tot_DeltaLen_Median**: Median size delta (P²).
119. **Tot_DeltaLen_Skew**: Skewness of size delta.
120. **Tot_DeltaLen_Kurt**: Kurtosis of size delta.
121. **Tot_DeltaLen_CoV**: Coefficient of Variation for size delta.
122. **Tot_DeltaLen_Mode**: Mode of size delta distribution.

## Statistical Suite: Fwd_DeltaLen (Forward Packet Length Delta)
123. **Fwd_DeltaLen_Max**: Maximum size delta in forward direction.
124. **Fwd_DeltaLen_Min**: Minimum forward size delta.
125. **Fwd_DeltaLen_Mean**: Mean forward size delta.
126. **Fwd_DeltaLen_Std**: Standard deviation of forward size delta.
127. **Fwd_DeltaLen_Var**: Variance of forward size delta.
128. **Fwd_DeltaLen_Median**: Median forward size delta.
129. **Fwd_DeltaLen_Skew**: Skewness of forward size delta.
130. **Fwd_DeltaLen_Kurt**: Kurtosis of forward size delta.
131. **Fwd_DeltaLen_CoV**: Coefficient of Variation for forward size delta.
132. **Fwd_DeltaLen_Mode**: Mode of forward size delta distribution.

## Statistical Suite: Bwd_DeltaLen (Backward Packet Length Delta)
133. **Bwd_DeltaLen_Max**: Maximum size delta in backward direction.
134. **Bwd_DeltaLen_Min**: Minimum backward size delta.
135. **Bwd_DeltaLen_Mean**: Mean backward size delta.
136. **Bwd_DeltaLen_Std**: Standard deviation of backward size delta.
137. **Bwd_DeltaLen_Var**: Variance of backward size delta.
138. **Bwd_DeltaLen_Median**: Median backward size delta.
139. **Bwd_DeltaLen_Skew**: Skewness of backward size delta.
140. **Bwd_DeltaLen_Kurt**: Kurtosis of backward size delta.
141. **Bwd_DeltaLen_CoV**: Coefficient of Variation for backward size delta.
142. **Bwd_DeltaLen_Mode**: Mode of backward size delta distribution.

## Statistical Suite: Win (TCP Window Size)
143. **Win_Max**: Maximum observed TCP window size.
144. **Win_Min**: Minimum observed TCP window size.
145. **Win_Mean**: Mean TCP window size.
146. **Win_Std**: Standard deviation of window size.
147. **Win_Var**: Variance of window size.
148. **Win_Median**: Median window size (P²).
149. **Win_Skew**: Skewness of window size distribution.
150. **Win_Kurt**: Kurtosis of window size distribution.
151. **Win_CoV**: Coefficient of Variation for TCP window.
152. **Win_Mode**: Mode of TCP window distribution.

## Statistical Suite: IpId (IP Identification)
153. **IpId_Max**: Maximum observed IP ID value.
154. **IpId_Min**: Minimum observed IP ID value.
155. **IpId_Mean**: Mean IP ID value.
156. **IpId_Std**: Standard deviation of IP ID.
157. **IpId_Var**: Variance of IP ID.
158. **IpId_Median**: Median IP ID (P²).
159. **IpId_Skew**: Skewness of IP ID distribution.
160. **IpId_Kurt**: Kurtosis of IP ID distribution.
161. **IpId_CoV**: Coefficient of Variation for IP ID.
162. **IpId_Mode**: Mode of IP ID distribution.

## Statistical Suite: Frag (Fragment Offset)
163. **Frag_Max**: Maximum fragment offset observed.
164. **Frag_Min**: Minimum fragment offset observed.
165. **Frag_Mean**: Mean fragment offset.
166. **Frag_Std**: Standard deviation of fragment offset.
167. **Frag_Var**: Variance of fragment offset.
168. **Frag_Median**: Median fragment offset (P²).
169. **Frag_Skew**: Skewness of fragment offset.
170. **Frag_Kurt**: Kurtosis of fragment offset.
171. **Frag_CoV**: Coefficient of Variation for fragmentation.
172. **Frag_Mode**: Mode of fragment offset distribution.

## Statistical Suite: TTL_Var (Time to Live Variance)
173. **TTL_Var_Max**: Maximum TTL value observed.
174. **TTL_Var_Min**: Minimum TTL value observed.
175. **TTL_Var_Mean**: Mean TTL value.
176. **TTL_Var_Std**: Standard deviation of TTL.
177. **TTL_Var_Var**: Variance of TTL (High variance indicates spoofed distribution).
178. **TTL_Var_Median**: Median TTL (P²).
179. **TTL_Var_Skew**: Skewness of TTL distribution.
180. **TTL_Var_Kurt**: Kurtosis of TTL distribution.
181. **TTL_Var_CoV**: Coefficient of Variation for TTL.
182. **TTL_Var_Mode**: Mode of TTL distribution.

## TCP Windows & Initial Flags
183. **FwdInitWinBytes**: Bytes sent in the initial window of the forward direction.
184. **BwdInitWinBytes**: Bytes sent in the initial window of the backward direction.

## TCP Flag Counters (Total, Forward, Backward)
185. **FIN_Cnt**: Total count of FIN flags.
186. **FIN_Fwd_Cnt**: FIN flags in forward direction.
187. **FIN_Bwd_Cnt**: FIN flags in backward direction.
188. **SYN_Cnt**: Total count of SYN flags.
189. **SYN_Fwd_Cnt**: SYN flags in forward direction.
190. **SYN_Bwd_Cnt**: SYN flags in backward direction.
191. **RST_Cnt**: Total count of RST flags.
192. **RST_Fwd_Cnt**: RST flags in forward direction.
193. **RST_Bwd_Cnt**: RST flags in backward direction.
194. **PSH_Cnt**: Total count of PSH flags.
195. **PSH_Fwd_Cnt**: PSH flags in forward direction.
196. **PSH_Bwd_Cnt**: PSH flags in backward direction.
197. **ACK_Cnt**: Total count of ACK flags.
198. **ACK_Fwd_Cnt**: ACK flags in forward direction.
199. **ACK_Bwd_Cnt**: ACK flags in backward direction.
200. **URG_Cnt**: Total count of URG flags.
201. **URG_Fwd_Cnt**: URG flags in forward direction.
202. **URG_Bwd_Cnt**: URG flags in backward direction.
203. **ECE_Cnt**: Total count of ECE flags.
204. **ECE_Fwd_Cnt**: ECE flags in forward direction.
205. **ECE_Bwd_Cnt**: ECE flags in backward direction.
206. **CWR_Cnt**: Total count of CWR flags.
207. **CWR_Fwd_Cnt**: CWR flags in forward direction.
208. **CWR_Bwd_Cnt**: CWR flags in backward direction.

## L3/L4/L7 Extraction Metrics
209. **PayloadEntropy**: Shannon entropy of the first 64 bytes of payload.
210. **IcmpType**: Observed ICMP type.
211. **IcmpCode**: Observed ICMP code.
212. **TTL**: Final Time-to-Live value observed.
213. **IcmpEchoId**: ICMP Echo ID (for identification of specific ping flows).

## Statistical Suite: Active (Active Session Time)
214. **Active_Max**: Maximum time the flow was active (ns).
215. **Active_Min**: Minimum time active.
216. **Active_Mean**: Mean active session time.
217. **Active_Std**: Standard deviation of active time.
218. **Active_Var**: Variance of active time.
219. **Active_Median**: Median active time (P²).
220. **Active_Skew**: Skewness of active time.
221. **Active_Kurt**: Kurtosis of active time.
222. **Active_CoV**: Coefficient of Variation for active time.
223. **Active_Mode**: Mode of active time distribution.

## Statistical Suite: Idle (Idle Session Time)
224. **Idle_Max**: Maximum time the flow remained idle (ns).
225. **Idle_Min**: Minimum idle time.
226. **Idle_Mean**: Mean idle session time.
227. **Idle_Std**: Standard deviation of idle time.
228. **Idle_Var**: Variance of idle time.
229. **Idle_Median**: Median idle time (P²).
230. **Idle_Skew**: Skewness of idle time.
231. **Idle_Kurt**: Kurtosis of idle time.
232. **Idle_CoV**: Coefficient of Variation for idle time.
233. **Idle_Mode**: Mode of idle time distribution.

## Flow Performance & Mass Transmission
234. **BytesRate**: Overall flow throughput (Bytes/s).
235. **FwdBytesRate**: Throughput in forward direction.
236. **BwdBytesRate**: Throughput in backward direction.
237. **PacketsRate**: Packet transmission rate (Packets/s).
238. **FwdPacketsRate**: Packet rate in forward direction.
239. **BwdPacketsRate**: Packet rate in backward direction.
240. **DownUpRatio**: Ratio of backward bytes to forward bytes.
241. **FwdBulkBytes**: Total bytes sent in forward bulk mode.
242. **FwdBulkPkts**: Total packets sent in forward bulk mode.
243. **FwdBulkCnt**: Count of forward bulk transitions.
244. **BwdBulkBytes**: Total bytes sent in backward bulk mode.
245. **BwdBulkPkts**: Total packets sent in backward bulk mode.
246. **BwdBulkCnt**: Count of backward bulk transitions.

## Application Layer & Tunnel Discovery
247. **DNSAnswerCount**: Number of resource records in DNS answers.
248. **DNSQueryType**: DNS Query Type (A, AAAA, MX, etc.).
249. **DNSQueryClass**: DNS Query Class (IN, etc.).
250. **TunnelId**: Encapsulation identifier (VXLAN VNI or GRE Key).
251. **TunnelType**: Tunnel protocol type (0=None, 1=GRE, 2=VXLAN).
252. **NTP_Mode**: NTP operational mode.
253. **NTP_Stratum**: NTP stratum level.
254. **SNMP_PDU_Type**: Parsed SNMP PDU classification.
255. **SSDP_Method**: Discovered SSDP HTTP method (M-SEARCH/NOTIFY).

## High-Resolution Histogram: Total Size (Bins 0-79)
256-335. **Hist_Tot_[0-79]**: 80 frequency bins for total packet sizes (Step: 20 bytes).

## High-Resolution Histogram: Forward Size (Bins 0-79)
336-415. **Hist_Fwd_[0-79]**: 80 frequency bins for forward packet sizes (Step: 20 bytes).

## High-Resolution Histogram: Backward Size (Bins 0-79)
416-495. **Hist_Bwd_[0-79]**: 80 frequency bins for backward packet sizes (Step: 20 bytes).

---
**Total Extracted Features: 495**
**Architecture**: Lynceus eBPF Data Plane (Kernel-space) + Welford/P² Statistical Engine (User-space).
