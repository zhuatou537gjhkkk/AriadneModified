/* src/utils/request.js */
import axios from 'axios';
import { message } from 'antd';

// 创建 axios 实例
const service = axios.create({
    // 这里的 /api/v1 对应后端接口文档的 Base URL
    // 开发环境通常在 vite.config.js 配置代理，或者直接填后端 IP
    baseURL: '/api/v1',
    timeout: 5000, // 请求超时时间
});

// 请求拦截器 (Request Interceptor)
service.interceptors.request.use(
    (config) => {
        // 如果有 Token，在这里统一注入
        const token = localStorage.getItem('token');
        if (token) {
            config.headers['Authorization'] = `Bearer ${token}`;
        }
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

// 响应拦截器 (Response Interceptor)
service.interceptors.response.use(
    (response) => {
        // 2xx 范围内的状态码都会触发该函数
        return response.data;
    },
    (error) => {
        // 超出 2xx 范围的状态码都会触发该函数
        console.log(response);
        const { response } = error;
        if (response) {
            // 请求已发出，但服务器响应的状态码不在 2xx 范围内
            message.error(`请求错误 ${response.status}: ${response.data.message || '未知错误'}`);
        } else {
            // 网络错误
            message.warning('网络连接异常，已切换至本地演示数据');
        }
        return Promise.reject(error);
    }
);

export default service;