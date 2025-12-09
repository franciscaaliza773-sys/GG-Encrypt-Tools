🔒 GG-Encrypt Tools
Secure Image Encryption & Privacy Protection for ComfyUI Workflows
ComfyUI 工作流隐私保护与图片加密工具

English | 中文

<a name="english"></a>

🇬🇧 English
Introduction
GG-Encrypt is a lightweight privacy protection suite designed for AI creators and developers. In the era of cloud computing, creators often need to run workflows on third-party cloud platforms (e.g., RunPod, AutoDL, Kaggle).

This tool solves a critical problem: How to securely download your generated images from public/cloud environments without privacy leakage.

By encrypting the output image into a "Visual Noise" PNG, it ensures that:

Data Privacy: Your creations are encrypted locally before transmission.
Intellectual Property: Protect your prompt info and workflow metadata embedded in images.
Secure Transmission: Prevent intermediate interception or unauthorized viewing during download.
Features
ComfyUI Node: Seamlessly integrates into your workflow. Encrypts output images instantly.
AES-GCM + RSA Encryption: Industry-standard encryption for maximum security.
Lossless Restoration: Decrypt to retrieve the original image/video perfectly.
Installation
Clone this repository into your ComfyUI/custom_nodes/ folder:
Bash

git clone https://github.com/YourUserName/GG-Encrypt-Tools.git
Restart ComfyUI.
Find the node under GG Tools -> GG IMGEncrypt.
<a name="中文"></a>

🇨🇳 中文
项目简介
GG-Encrypt 是一套专为 AI 创作者设计的轻量级隐私保护工具。在云端算力普及的今天，创作者经常需要在第三方云平台（如 AutoDL、阿里云、等）运行 ComfyUI 工作流。

本工具旨在解决一个核心痛点：如何在公共云环境或不可信网络下，安全地将生成结果传输回本地。

通过将输出图片加密为“彩色噪点” PNG，它实现了：

隐私保护： 图片生成后立即加密，防止在云端存储或传输过程中被窥探。
知识产权保护： 保护图片中内嵌的 Prompt 和工作流元数据不被第三方提取。
安全传输： 即使下载链接泄露，没有私钥和密码也无法查看原图。
主要功能
ComfyUI 专用节点： 完美集成到现有工作流，接在 SaveImage 之前即可使用。
高强度加密： 采用 AES-GCM (数据加密) + RSA 标准算法。
无损还原： 解密后 100% 还原原始图片/视频文件，无画质损失。
如何安装
进入你的 ComfyUI 插件目录：
Bash

cd ComfyUI/custom_nodes/
克隆本仓库：
Bash

git clone https://github.com/你的用户名/GG-Encrypt-Tools.git
重启 ComfyUI，在节点菜单 GG Tools 中即可找到。
隐私声明 / Privacy Policy
本工具仅提供数据加密技术手段，用于保障用户数据的传输安全与隐私。用户请勿利用本工具存储或传播任何违反当地法律法规的内容。
This tool is provided for data security and privacy protection purposes only.
