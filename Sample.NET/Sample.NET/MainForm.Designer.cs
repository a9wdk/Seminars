using System.Windows.Forms;

namespace Test_sample {

    partial class MainForm {

        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing) {
            if (disposing && (components != null)) {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Код, автоматически созданный конструктором форм Windows 

        private void InitializeComponent() {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(MainForm));
            this.menuStripMainForm = new System.Windows.Forms.MenuStrip();
            this.fileToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.exitToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.function1ToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.start_F1_MenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.stop_F1_MenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.function2ToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.start_F2_MenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.stop_F2_MenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.helpToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.aboutToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.rTB1 = new System.Windows.Forms.RichTextBox();
            this.rTB2 = new System.Windows.Forms.RichTextBox();
            this.menuStripMainForm.SuspendLayout();
            this.SuspendLayout();
            // 
            // menuStripMainForm
            // 
            this.menuStripMainForm.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.fileToolStripMenuItem,
            this.function1ToolStripMenuItem,
            this.function2ToolStripMenuItem,
            this.helpToolStripMenuItem});
            this.menuStripMainForm.Location = new System.Drawing.Point(0, 0);
            this.menuStripMainForm.Name = "menuStripMainForm";
            this.menuStripMainForm.Size = new System.Drawing.Size(855, 24);
            this.menuStripMainForm.TabIndex = 0;
            this.menuStripMainForm.Text = "menuStripMainForm";
            // 
            // fileToolStripMenuItem
            // 
            this.fileToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.exitToolStripMenuItem});
            this.fileToolStripMenuItem.Name = "fileToolStripMenuItem";
            this.fileToolStripMenuItem.Size = new System.Drawing.Size(37, 20);
            this.fileToolStripMenuItem.Text = "File";
            // 
            // exitToolStripMenuItem
            // 
            this.exitToolStripMenuItem.Name = "exitToolStripMenuItem";
            this.exitToolStripMenuItem.Size = new System.Drawing.Size(92, 22);
            this.exitToolStripMenuItem.Text = "Exit";
            this.exitToolStripMenuItem.Click += new System.EventHandler(this.Menu_Exit);
            // 
            // function1ToolStripMenuItem
            // 
            this.function1ToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.start_F1_MenuItem,
            this.stop_F1_MenuItem});
            this.function1ToolStripMenuItem.Name = "function1ToolStripMenuItem";
            this.function1ToolStripMenuItem.Size = new System.Drawing.Size(72, 20);
            this.function1ToolStripMenuItem.Text = "Function1";
            // 
            // start_F1_MenuItem
            // 
            this.start_F1_MenuItem.Name = "start_F1_MenuItem";
            this.start_F1_MenuItem.Size = new System.Drawing.Size(98, 22);
            this.start_F1_MenuItem.Text = "Start";
            this.start_F1_MenuItem.Click += new System.EventHandler(this.Menu_Start_F1);
            // 
            // stop_F1_MenuItem
            // 
            this.stop_F1_MenuItem.Enabled = false;
            this.stop_F1_MenuItem.Name = "stop_F1_MenuItem";
            this.stop_F1_MenuItem.Size = new System.Drawing.Size(98, 22);
            this.stop_F1_MenuItem.Text = "Stop";
            this.stop_F1_MenuItem.Click += new System.EventHandler(this.Menu_Stop_F1);
            // 
            // function2ToolStripMenuItem
            // 
            this.function2ToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.start_F2_MenuItem,
            this.stop_F2_MenuItem});
            this.function2ToolStripMenuItem.Name = "function2ToolStripMenuItem";
            this.function2ToolStripMenuItem.Size = new System.Drawing.Size(72, 20);
            this.function2ToolStripMenuItem.Text = "Function2";
            // 
            // start_F2_MenuItem
            // 
            this.start_F2_MenuItem.Name = "start_F2_MenuItem";
            this.start_F2_MenuItem.Size = new System.Drawing.Size(98, 22);
            this.start_F2_MenuItem.Text = "Start";
            this.start_F2_MenuItem.Click += new System.EventHandler(this.Menu_Start_F2);
            // 
            // stop_F2_MenuItem
            // 
            this.stop_F2_MenuItem.Enabled = false;
            this.stop_F2_MenuItem.Name = "stop_F2_MenuItem";
            this.stop_F2_MenuItem.Size = new System.Drawing.Size(98, 22);
            this.stop_F2_MenuItem.Text = "Stop";
            this.stop_F2_MenuItem.Click += new System.EventHandler(this.Menu_Stop_F2);
            // 
            // helpToolStripMenuItem
            // 
            this.helpToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.aboutToolStripMenuItem});
            this.helpToolStripMenuItem.Name = "helpToolStripMenuItem";
            this.helpToolStripMenuItem.Size = new System.Drawing.Size(44, 20);
            this.helpToolStripMenuItem.Text = "Help";
            // 
            // aboutToolStripMenuItem
            // 
            this.aboutToolStripMenuItem.Name = "aboutToolStripMenuItem";
            this.aboutToolStripMenuItem.Size = new System.Drawing.Size(116, 22);
            this.aboutToolStripMenuItem.Text = "About...";
            this.aboutToolStripMenuItem.Click += new System.EventHandler(this.Menu_About);
            // 
            // rTB1
            // 
            this.rTB1.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)
                        | System.Windows.Forms.AnchorStyles.Left)));
            this.rTB1.BackColor = System.Drawing.SystemColors.Window;
            this.rTB1.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.rTB1.Font = new System.Drawing.Font("Courier New", 12F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.rTB1.ForeColor = System.Drawing.Color.ForestGreen;
            this.rTB1.Location = new System.Drawing.Point(5, 24);
            this.rTB1.MaxLength = 65535;
            this.rTB1.Name = "rTB1";
            this.rTB1.ReadOnly = true;
            this.rTB1.ScrollBars = System.Windows.Forms.RichTextBoxScrollBars.None;
            this.rTB1.Size = new System.Drawing.Size(422, 544);
            this.rTB1.TabIndex = 1;
            this.rTB1.TabStop = false;
            this.rTB1.Text = "";
            // 
            // rTB2
            // 
            this.rTB2.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.rTB2.BackColor = System.Drawing.SystemColors.Window;
            this.rTB2.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.rTB2.Font = new System.Drawing.Font("Courier New", 12F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.rTB2.ForeColor = System.Drawing.Color.ForestGreen;
            this.rTB2.Location = new System.Drawing.Point(433, 24);
            this.rTB2.MaxLength = 65535;
            this.rTB2.Name = "rTB2";
            this.rTB2.ReadOnly = true;
            this.rTB2.ScrollBars = System.Windows.Forms.RichTextBoxScrollBars.None;
            this.rTB2.Size = new System.Drawing.Size(422, 544);
            this.rTB2.TabIndex = 1;
            this.rTB2.TabStop = false;
            this.rTB2.Text = "";
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.SystemColors.Window;
            this.ClientSize = new System.Drawing.Size(855, 568);
            this.Controls.Add(this.rTB2);
            this.Controls.Add(this.rTB1);
            this.Controls.Add(this.menuStripMainForm);
            this.DoubleBuffered = true;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MainMenuStrip = this.menuStripMainForm;
            this.Name = "MainForm";
            this.Resize += new System.EventHandler(this.MainFormResize);
            this.menuStripMainForm.ResumeLayout(false);
            this.menuStripMainForm.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.MenuStrip menuStripMainForm;
        private System.Windows.Forms.ToolStripMenuItem fileToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem exitToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem function1ToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem start_F1_MenuItem;
        private System.Windows.Forms.ToolStripMenuItem stop_F1_MenuItem;
        private System.Windows.Forms.ToolStripMenuItem function2ToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem start_F2_MenuItem;
        private System.Windows.Forms.ToolStripMenuItem stop_F2_MenuItem;
        private System.Windows.Forms.ToolStripMenuItem helpToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem aboutToolStripMenuItem;
        private System.Windows.Forms.RichTextBox rTB1;
        private System.Windows.Forms.RichTextBox rTB2;
    }
}

