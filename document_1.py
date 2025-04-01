import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog, ttk
import hashlib
import os
import pickle
from cryptography.fernet import Fernet
import base64
from tkinter.font import Font

class PasswordManager:
    def __init__(self):
        # 主窗口设置
        self.root = tk.Tk()
        self.root.title("密码保险箱")
        self.root.geometry("800x500")
        self.root.configure(bg="#f5f5f7")
        
        # 设置主题颜色
        self.primary_color = "#0078d7"  # 主色调
        self.bg_color = "#f5f5f7"       # 背景色
        self.accent_color = "#007aff"   # 强调色
        self.text_color = "#333333"     # 文字色
        
        # 设置字体
        self.title_font = Font(family="Helvetica", size=12, weight="bold")
        self.normal_font = Font(family="Helvetica", size=10)
        self.small_font = Font(family="Helvetica", size=9)
        
        # 访问密码哈希值 - 默认密码为 "admin123"
        self.access_password_hash = "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"  # SHA-256 of "admin123"
        
        # 加密密钥
        self.key = None
        
        # 账号数据存储
        self.accounts = []
        
        # 当前加载的文件
        self.current_file = None
        
        # 应用样式
        self.apply_style()
        
        # 创建界面组件
        self.create_widgets()
        
        # 设置列宽
        self.account_listbox.column("平台", width=120)
        self.account_listbox.column("账号", width=150)
        self.account_listbox.column("密码", width=150)
        self.account_listbox.column("注释", width=250)
        
    def apply_style(self):
        # 配置ttk样式
        style = ttk.Style()
        style.theme_use('clam')  # 使用clam主题作为基础
        
        # 配置Treeview样式
        style.configure("Treeview", 
                        background=self.bg_color,
                        foreground=self.text_color,
                        rowheight=25,
                        fieldbackground=self.bg_color)
        
        style.configure("Treeview.Heading", 
                        font=('Helvetica', 10, 'bold'),
                        background=self.primary_color,
                        foreground="white")
        
        # 选中行的样式
        style.map('Treeview', 
                 background=[('selected', self.accent_color)],
                 foreground=[('selected', 'white')])
        
        # 按钮样式
        style.configure("Accent.TButton", 
                        font=self.normal_font,
                        background=self.accent_color,
                        foreground="white")
        
        style.map("Accent.TButton",
                  background=[('active', self.primary_color)],
                  relief=[('pressed', 'sunken')])

    def create_widgets(self):
        # 创建菜单栏
        menu_bar = tk.Menu(self.root)
        
        # 文件菜单
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="新建", command=self.create_new_file)
        file_menu.add_command(label="打开", command=self.open_file)
        file_menu.add_command(label="保存", command=self.save_file)
        file_menu.add_command(label="另存为", command=self.save_as_file)
        file_menu.add_separator()
        file_menu.add_command(label="导出为文本", command=self.export_to_txt)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.root.quit)
        menu_bar.add_cascade(label="文件", menu=file_menu)
        
        # 编辑菜单
        edit_menu = tk.Menu(menu_bar, tearoff=0)
        edit_menu.add_command(label="添加账号", command=self.add_account)
        edit_menu.add_command(label="编辑账号", command=self.edit_account)
        edit_menu.add_command(label="删除账号", command=self.delete_account)
        menu_bar.add_cascade(label="编辑", menu=edit_menu)
        
        # 视图菜单
        view_menu = tk.Menu(menu_bar, tearoff=0)
        self.show_passwords_var = tk.BooleanVar(value=False)
        view_menu.add_checkbutton(label="显示密码", variable=self.show_passwords_var, command=self.toggle_password_visibility)
        menu_bar.add_cascade(label="视图", menu=view_menu)
        
        # 帮助菜单
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="关于", command=self.show_about)
        menu_bar.add_cascade(label="帮助", menu=help_menu)
        
        self.root.config(menu=menu_bar)
        
        # 主框架
        main_frame = tk.Frame(self.root, bg=self.bg_color)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        
        # 标题与描述
        header_frame = tk.Frame(main_frame, bg=self.bg_color)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(header_frame, text="密码保险箱", font=("Helvetica", 16, "bold"), 
                 bg=self.bg_color, fg=self.primary_color).pack(side=tk.LEFT)
        
        info_text = "安全存储和管理您的所有密码"
        tk.Label(header_frame, text=info_text, font=self.small_font,
                 bg=self.bg_color, fg="#666666").pack(side=tk.LEFT, padx=10)
        
        # 账号操作框架 - 使用更现代的按钮样式
        operation_frame = tk.Frame(main_frame, bg=self.bg_color)
        operation_frame.pack(fill=tk.X, pady=5)
        
        # 创建按钮
        btn_frame = tk.Frame(operation_frame, bg=self.bg_color)
        btn_frame.pack(side=tk.LEFT)
        
        ttk.Button(btn_frame, text="添加账号", command=self.add_account, style="Accent.TButton", width=12).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_frame, text="编辑账号", command=self.edit_account, width=12).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_frame, text="删除账号", command=self.delete_account, width=12).pack(side=tk.LEFT, padx=3)
        
        # 添加显示密码开关
        password_frame = tk.Frame(operation_frame, bg=self.bg_color)
        password_frame.pack(side=tk.RIGHT)
        
        self.show_password_btn = tk.Checkbutton(password_frame, text="显示密码", 
                                              variable=self.show_passwords_var,
                                              command=self.toggle_password_visibility,
                                              bg=self.bg_color, fg=self.text_color,
                                              activebackground=self.bg_color,
                                              font=self.normal_font)
        self.show_password_btn.pack(side=tk.RIGHT)
        
        # 搜索框 - 现代风格
        search_frame = tk.Frame(main_frame, bg=self.bg_color)
        search_frame.pack(fill=tk.X, pady=10)
        
        search_icon_label = tk.Label(search_frame, text="🔍", font=("Helvetica", 12), bg=self.bg_color)
        search_icon_label.pack(side=tk.LEFT)
        
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.filter_accounts)
        
        search_entry = tk.Entry(search_frame, textvariable=self.search_var, 
                               font=self.normal_font, width=40,
                               relief=tk.SOLID, bd=1)
        search_entry.pack(side=tk.LEFT, padx=5, ipady=5)
        search_entry.insert(0, "搜索...")
        
        # 焦点事件处理
        def on_entry_click(event):
            if search_entry.get() == "搜索...":
                search_entry.delete(0, tk.END)
                search_entry.config(fg=self.text_color)
        
        def on_focus_out(event):
            if search_entry.get() == "":
                search_entry.insert(0, "搜索...")
                search_entry.config(fg="gray")
                
        search_entry.bind("<FocusIn>", on_entry_click)
        search_entry.bind("<FocusOut>", on_focus_out)
        search_entry.config(fg="gray")
        
        # 账号列表框架 - 使用圆角边框和阴影效果
        list_container = tk.Frame(main_frame, bg=self.bg_color, bd=0, 
                                 highlightbackground="#dddddd", highlightthickness=1)
        list_container.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 创建树形视图
        self.account_listbox = ttk.Treeview(list_container, 
                                         columns=("平台", "账号", "密码", "注释"),
                                         show="headings",
                                         selectmode="browse")
        
        self.account_listbox.heading("平台", text="平台")
        self.account_listbox.heading("账号", text="账号")
        self.account_listbox.heading("密码", text="密码")
        self.account_listbox.heading("注释", text="注释")
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(list_container, orient="vertical", command=self.account_listbox.yview)
        self.account_listbox.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.account_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # 双击编辑
        self.account_listbox.bind("<Double-1>", lambda event: self.edit_account())
        
        # 右键菜单
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="编辑", command=self.edit_account)
        self.context_menu.add_command(label="删除", command=self.delete_account)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="复制用户名", command=lambda: self.copy_to_clipboard("username"))
        self.context_menu.add_command(label="复制密码", command=lambda: self.copy_to_clipboard("password"))
        
        self.account_listbox.bind("<Button-3>", self.show_context_menu)
        
        # 状态栏
        status_frame = tk.Frame(self.root, bg="#e6e6e6", bd=1, relief=tk.SUNKEN)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        status_bar = tk.Label(status_frame, textvariable=self.status_var, bg="#e6e6e6", 
                              fg="#555555", anchor=tk.W, padx=10, pady=2, font=self.small_font)
        status_bar.pack(side=tk.LEFT, fill=tk.X)
        
        # 在状态栏右侧显示记录数量
        self.count_var = tk.StringVar()
        self.count_var.set("0 个账号")
        count_label = tk.Label(status_frame, textvariable=self.count_var, bg="#e6e6e6", 
                               fg="#555555", padx=10, pady=2, font=self.small_font)
        count_label.pack(side=tk.RIGHT)

    def create_new_file(self):
        if self.accounts and messagebox.askyesno("保存确认", "是否保存当前数据?"):
            self.save_file()
        
        password = simpledialog.askstring("设置访问密码", "请设置访问密码:")#, show='*')
        if password:
            self.access_password_hash = hashlib.sha256(password.encode()).hexdigest()
            self.key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
            self.accounts = []
            self.update_account_list()
            self.current_file = None
            self.status_var.set("已创建新文件，请使用'保存'保存文件")
        else:
            messagebox.showwarning("警告", "必须设置访问密码!")

    def open_file(self):
        file_path = filedialog.askopenfilename(defaultextension=".bin", filetypes=[("加密密码文件", "*.bin"), ("所有文件", "*.*")])
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    data = pickle.load(f)
                
                password = simpledialog.askstring("验证", "请输入访问密码:", show='*')
                if password is None:
                    return
                    
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                if password_hash != data['hash']:
                    messagebox.showerror("错误", "访问密码不正确!")
                    return
                
                self.access_password_hash = data['hash']
                self.key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
                
                # 解密数据
                cipher = Fernet(self.key)
                encrypted_accounts = data['accounts']
                decrypted_data = cipher.decrypt(encrypted_accounts)
                self.accounts = pickle.loads(decrypted_data)
                
                self.update_account_list()
                self.current_file = file_path
                self.status_var.set(f"已打开文件: {os.path.basename(file_path)}")
                
            except Exception as e:
                messagebox.showerror("错误", f"无法打开文件: {str(e)}")

    def save_file(self):
        if not self.key:
            messagebox.showerror("错误", "未设置加密密钥!")
            return
            
        if not self.current_file:
            return self.save_as_file()
        
        try:
            # 加密数据
            cipher = Fernet(self.key)
            accounts_data = pickle.dumps(self.accounts)
            encrypted_data = cipher.encrypt(accounts_data)
            
            # 保存数据
            data = {
                'hash': self.access_password_hash,
                'accounts': encrypted_data
            }
            
            with open(self.current_file, 'wb') as f:
                pickle.dump(data, f)
                
            self.status_var.set(f"已保存到文件: {os.path.basename(self.current_file)}")
            
        except Exception as e:
            messagebox.showerror("错误", f"无法保存文件: {str(e)}")
    
    def save_as_file(self):
        if not self.key:
            messagebox.showerror("错误", "未设置加密密钥!")
            return
            
        file_path = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("加密密码文件", "*.bin"), ("所有文件", "*.*")])
        if file_path:
            self.current_file = file_path
            self.save_file()
            return True
        return False

    def export_to_txt(self):
        if not self.accounts:
            messagebox.showinfo("提示", "没有账号数据可导出")
            return
            
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("平台\t账号\t密码\t注释\n")
                    f.write("="*50 + "\n")
                    for account in self.accounts:
                        f.write(f"{account['platform']}\t{account['username']}\t{account['password']}\t{account['note']}\n")
                        
                self.status_var.set(f"已导出到文本文件: {os.path.basename(file_path)}")
                messagebox.showinfo("导出成功", f"已导出 {len(self.accounts)} 条账号记录")
                
            except Exception as e:
                messagebox.showerror("错误", f"导出失败: {str(e)}")

    def add_account(self):
        if not self.key:
            messagebox.showerror("错误", "请先创建或打开一个密码文件!")
            return
            
        # 创建对话框
        dialog = tk.Toplevel(self.root)
        dialog.title("添加账号")
        dialog.geometry("420x300")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=self.bg_color)
        
        # 添加标题
        title_frame = tk.Frame(dialog, bg=self.bg_color)
        title_frame.pack(fill=tk.X, padx=20, pady=(15, 10))
        tk.Label(title_frame, text="添加新账号", font=self.title_font, bg=self.bg_color, fg=self.primary_color).pack(anchor="w")
        
        # 表单容器
        form_frame = tk.Frame(dialog, bg=self.bg_color)
        form_frame.pack(fill=tk.BOTH, padx=20, pady=5, expand=True)
        
        # 表单元素
        labels = ["平台:", "账号:", "密码:", "注释:"]
        for i, text in enumerate(labels):
            tk.Label(form_frame, text=text, font=self.normal_font, bg=self.bg_color, fg=self.text_color).grid(
                row=i, column=0, sticky="e", padx=10, pady=8)
        
        platform_var = tk.StringVar()
        username_var = tk.StringVar()
        password_var = tk.StringVar()
        note_var = tk.StringVar()
        
        platform_entry = tk.Entry(form_frame, textvariable=platform_var, width=30, font=self.normal_font)
        username_entry = tk.Entry(form_frame, textvariable=username_var, width=30, font=self.normal_font)
        password_entry = tk.Entry(form_frame, textvariable=password_var, width=30, font=self.normal_font, show="*")
        note_entry = tk.Entry(form_frame, textvariable=note_var, width=30, font=self.normal_font)
        
        platform_entry.grid(row=0, column=1, padx=10, pady=8, sticky="w")
        username_entry.grid(row=1, column=1, padx=10, pady=8, sticky="w")
        password_entry.grid(row=2, column=1, padx=10, pady=8, sticky="w")
        note_entry.grid(row=3, column=1, padx=10, pady=8, sticky="w")
        
        # 显示密码按钮
        def toggle_password():
            if password_entry.cget('show') == '*':
                password_entry.config(show='')
                show_btn.config(text='隐藏')
            else:
                password_entry.config(show='*')
                show_btn.config(text='显示')
                
        show_btn = tk.Button(form_frame, text="显示", command=toggle_password,
                           font=self.small_font, bd=0, fg=self.accent_color,
                           activeforeground=self.primary_color, bg=self.bg_color,
                           activebackground=self.bg_color, cursor="hand2")
        show_btn.grid(row=2, column=2, padx=5)
        
        def submit():
            platform = platform_var.get().strip()
            username = username_var.get().strip()
            password = password_var.get()
            note = note_var.get().strip()
            
            if not platform or not username or not password:
                messagebox.showerror("错误", "平台、账号和密码不能为空!", parent=dialog)
                return
                
            account = {
                'platform': platform,
                'username': username,
                'password': password,
                'note': note
            }
            
            self.accounts.append(account)
            self.update_account_list()
            dialog.destroy()
            self.status_var.set("账号已添加")
        
        # 按钮区域
        btn_frame = tk.Frame(dialog, bg=self.bg_color)
        btn_frame.pack(fill=tk.X, padx=20, pady=15)
        
        cancel_btn = tk.Button(btn_frame, text="取消", command=dialog.destroy,
                            width=8, font=self.normal_font, relief=tk.GROOVE,
                            bg="#f5f5f7", activebackground="#e5e5e7")
        cancel_btn.pack(side=tk.RIGHT, padx=5)
        
        save_btn = tk.Button(btn_frame, text="保存", command=submit,
                          width=8, font=self.normal_font, relief=tk.GROOVE,
                          bg=self.accent_color, fg="white",
                          activebackground=self.primary_color, activeforeground="white")
        save_btn.pack(side=tk.RIGHT, padx=5)
        
        platform_entry.focus_set()

    def edit_account(self):
        if not self.account_listbox.selection():
            messagebox.showinfo("提示", "请先选择一个账号")
            return
            
        item_id = self.account_listbox.selection()[0]
        item_index = self.account_listbox.index(item_id)
        account = self.accounts[item_index]
        
        # 创建对话框
        dialog = tk.Toplevel(self.root)
        dialog.title("编辑账号")
        dialog.geometry("420x300")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=self.bg_color)
        
        # 添加标题
        title_frame = tk.Frame(dialog, bg=self.bg_color)
        title_frame.pack(fill=tk.X, padx=20, pady=(15, 10))
        tk.Label(title_frame, text="编辑账号", font=self.title_font, bg=self.bg_color, fg=self.primary_color).pack(anchor="w")
        
        # 表单容器
        form_frame = tk.Frame(dialog, bg=self.bg_color)
        form_frame.pack(fill=tk.BOTH, padx=20, pady=5, expand=True)
        
        # 表单元素
        labels = ["平台:", "账号:", "密码:", "注释:"]
        for i, text in enumerate(labels):
            tk.Label(form_frame, text=text, font=self.normal_font, bg=self.bg_color, fg=self.text_color).grid(
                row=i, column=0, sticky="e", padx=10, pady=8)
        
        platform_var = tk.StringVar(value=account['platform'])
        username_var = tk.StringVar(value=account['username'])
        password_var = tk.StringVar(value=account['password'])
        note_var = tk.StringVar(value=account['note'])
        
        platform_entry = tk.Entry(form_frame, textvariable=platform_var, width=30, font=self.normal_font)
        username_entry = tk.Entry(form_frame, textvariable=username_var, width=30, font=self.normal_font)
        password_entry = tk.Entry(form_frame, textvariable=password_var, width=30, font=self.normal_font, show="*")
        note_entry = tk.Entry(form_frame, textvariable=note_var, width=30, font=self.normal_font)
        
        platform_entry.grid(row=0, column=1, padx=10, pady=8, sticky="w")
        username_entry.grid(row=1, column=1, padx=10, pady=8, sticky="w")
        password_entry.grid(row=2, column=1, padx=10, pady=8, sticky="w")
        note_entry.grid(row=3, column=1, padx=10, pady=8, sticky="w")
        
        # 显示密码按钮
        def toggle_password():
            if password_entry.cget('show') == '*':
                password_entry.config(show='')
                show_btn.config(text='隐藏')
            else:
                password_entry.config(show='*')
                show_btn.config(text='显示')
                
        show_btn = tk.Button(form_frame, text="显示", command=toggle_password,
                           font=self.small_font, bd=0, fg=self.accent_color,
                           activeforeground=self.primary_color, bg=self.bg_color,
                           activebackground=self.bg_color, cursor="hand2")
        show_btn.grid(row=2, column=2, padx=5)
        
        def submit():
            platform = platform_var.get().strip()
            username = username_var.get().strip()
            password = password_var.get()
            note = note_var.get().strip()
            
            if not platform or not username or not password:
                messagebox.showerror("错误", "平台、账号和密码不能为空!", parent=dialog)
                return
                
            self.accounts[item_index] = {
                'platform': platform,
                'username': username,
                'password': password,
                'note': note
            }
            
            self.update_account_list()
            dialog.destroy()
            self.status_var.set("账号已更新")
        
        # 按钮区域
        btn_frame = tk.Frame(dialog, bg=self.bg_color)
        btn_frame.pack(fill=tk.X, padx=20, pady=15)
        
        cancel_btn = tk.Button(btn_frame, text="取消", command=dialog.destroy,
                            width=8, font=self.normal_font, relief=tk.GROOVE,
                            bg="#f5f5f7", activebackground="#e5e5e7")
        cancel_btn.pack(side=tk.RIGHT, padx=5)
        
        save_btn = tk.Button(btn_frame, text="保存", command=submit,
                          width=8, font=self.normal_font, relief=tk.GROOVE,
                          bg=self.accent_color, fg="white",
                          activebackground=self.primary_color, activeforeground="white")
        save_btn.pack(side=tk.RIGHT, padx=5)

    def delete_account(self):
        if not self.account_listbox.selection():
            messagebox.showinfo("提示", "请先选择一个账号")
            return
            
        item_id = self.account_listbox.selection()[0]
        item_index = self.account_listbox.index(item_id)
        
        account = self.accounts[item_index]
        if messagebox.askyesno("确认删除", f"确定要删除 {account['platform']} 的账号 {account['username']} 吗?"):
            del self.accounts[item_index]
            self.update_account_list()
            self.status_var.set("账号已删除")

    def filter_accounts(self, *args):
        self.update_account_list()

    def update_account_list(self):
        # 清空列表
        if not hasattr(self, 'account_listbox'):  # Check if account_listbox is created
            return  # Exit if account_listbox is not initialized
       
        for item in self.account_listbox.get_children():
            self.account_listbox.delete(item)
            
        # 获取搜索关键词
        search_text = self.search_var.get().lower()
        if search_text == "搜索...":
            search_text = ""
            
        # 显示的账号数量
        display_count = 0
        
        # 根据关键词过滤并添加数据
        for account in self.accounts:
            if (search_text in account['platform'].lower() or 
                search_text in account['username'].lower() or 
                search_text in account['note'].lower()):
                
                # 根据显示密码选项决定密码的显示方式
                if self.show_passwords_var.get():
                    password_display = account['password']
                else:
                    password_display = "*" * len(account['password'])
                
                self.account_listbox.insert("", "end", values=(
                    account['platform'],
                    account['username'],
                    password_display,
                    account['note']
                ))
                display_count += 1
        
        # 更新状态栏的记录计数
        self.count_var.set(f"{display_count} / {len(self.accounts)} 个账号")
        
    def toggle_password_visibility(self):
        # 根据复选框状态更新密码显示
        self.update_account_list()
        if self.show_passwords_var.get():
            self.status_var.set("密码已显示")
        else:
            self.status_var.set("密码已隐藏")

    def show_context_menu(self, event):
        # 显示右键菜单
        if self.account_listbox.selection():
            self.context_menu.post(event.x_root, event.y_root)

    def copy_to_clipboard(self, field_type):
        """复制账号或密码到剪贴板"""
        if not self.account_listbox.selection():
            return
            
        item_id = self.account_listbox.selection()[0]
        item_index = self.account_listbox.index(item_id)
        account = self.accounts[item_index]
        
        # 清除剪贴板
        self.root.clipboard_clear()
        
        if field_type == "username":
            self.root.clipboard_append(account['username'])
            self.status_var.set("已复制用户名到剪贴板")
        elif field_type == "password":
            self.root.clipboard_append(account['password'])
            self.status_var.set("已复制密码到剪贴板")
            
    def show_about(self):
        """显示关于对话框"""
        about_dialog = tk.Toplevel(self.root)
        about_dialog.title("关于密码保险箱")
        about_dialog.geometry("400x300")
        about_dialog.resizable(False, False)
        about_dialog.transient(self.root)
        about_dialog.grab_set()
        about_dialog.configure(bg=self.bg_color)
        
        # 滚动区域
        frame = tk.Frame(about_dialog, bg=self.bg_color)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 应用标题
        tk.Label(frame, text="密码保险箱", font=("Helvetica", 16, "bold"), 
                 bg=self.bg_color, fg=self.primary_color).pack(pady=(0, 10))
        
        # 版本信息
        tk.Label(frame, text="版本 1.0.2", font=self.normal_font,
                bg=self.bg_color, fg=self.text_color).pack()
        
        # 应用描述
        description = """
        密码保险箱是一个安全、简便的密码管理工具，
        使用高级加密技术保护您的账号密码数据。
        
        功能特点:
        • 安全存储各类网站和应用的账号密码
        • 使用Fernet对称加密算法加密所有数据
        • 密码仅以哈希值形式存储
        • 支持导出密码到文本文件
        • 方便的搜索功能
        
        使用AES-128加密技术保护您的数据安全。
        """
        
        text_widget = tk.Text(frame, wrap=tk.WORD, height=10, width=40, 
                            font=self.small_font, bg=self.bg_color,
                            relief=tk.FLAT, borderwidth=0)
        text_widget.insert(tk.END, description)
        text_widget.config(state=tk.DISABLED)  # 设为只读
        text_widget.pack(pady=10, fill=tk.BOTH)
        
        # 关闭按钮
        tk.Button(frame, text="关闭", command=about_dialog.destroy,
                 width=10, bg=self.accent_color, fg="white",
                 activeforeground="white", activebackground=self.primary_color,
                 font=self.normal_font).pack(pady=10)

    def run(self):
        # 设置窗口图标（如果有）
        try:
            # 尝试获取窗口管理器
            self.root.iconbitmap("padlock.ico")  # 需要一个.ico文件放在同一目录下
        except:
            pass  # 忽略错误，无图标时继续运行
            
        # 启动应用
        self.root.mainloop()

if __name__ == "__main__":
    # 检查必要的依赖
    try:
        import cryptography
    except ImportError:
        print("正在安装必要的依赖...")
        import subprocess
        subprocess.check_call(["pip", "install", "cryptography"])
        
    app = PasswordManager()
    app.run()