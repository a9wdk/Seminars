namespace Test_sample {
    partial class AboutBox {

        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing) {
            if (disposing && (components != null)) {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Код, автоматически созданный конструктором форм Windows 

        private void InitializeComponent() {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(AboutBox));
            this.SRM_Logo = new System.Windows.Forms.PictureBox();
            this.buttonOK = new System.Windows.Forms.Button();
            this.Sample_Description = new System.Windows.Forms.TextBox();
            this.Sample_Copyright = new System.Windows.Forms.TextBox();
            this.Sample_Version = new System.Windows.Forms.TextBox();
            ((System.ComponentModel.ISupportInitialize)(this.SRM_Logo)).BeginInit();
            this.SuspendLayout();
            // 
            // SRM_Logo
            // 
            this.SRM_Logo.Image = ((System.Drawing.Image)(resources.GetObject("SRM_Logo.Image")));
            this.SRM_Logo.Location = new System.Drawing.Point(12, 12);
            this.SRM_Logo.Name = "SRM_Logo";
            this.SRM_Logo.Size = new System.Drawing.Size(131, 52);
            this.SRM_Logo.SizeMode = System.Windows.Forms.PictureBoxSizeMode.AutoSize;
            this.SRM_Logo.TabIndex = 0;
            this.SRM_Logo.TabStop = false;
            // 
            // buttonOK
            // 
            this.buttonOK.Location = new System.Drawing.Point(462, 12);
            this.buttonOK.Name = "buttonOK";
            this.buttonOK.Size = new System.Drawing.Size(50, 52);
            this.buttonOK.TabIndex = 1;
            this.buttonOK.Text = "OK";
            this.buttonOK.UseVisualStyleBackColor = true;
            this.buttonOK.Click += new System.EventHandler(this.buttonOK_Click);
            // 
            // Sample_Description
            // 
            this.Sample_Description.BackColor = System.Drawing.SystemColors.Control;
            this.Sample_Description.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.Sample_Description.Font = new System.Drawing.Font("Tahoma", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.Sample_Description.Location = new System.Drawing.Point(12, 78);
            this.Sample_Description.Multiline = true;
            this.Sample_Description.Name = "Sample_Description";
            this.Sample_Description.Size = new System.Drawing.Size(500, 138);
            this.Sample_Description.TabIndex = 2;
            this.Sample_Description.Text = resources.GetString("Sample_Description.Text");
            // 
            // Sample_Copyright
            // 
            this.Sample_Copyright.BackColor = System.Drawing.SystemColors.Control;
            this.Sample_Copyright.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.Sample_Copyright.Font = new System.Drawing.Font("Tahoma", 9.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.Sample_Copyright.Location = new System.Drawing.Point(159, 41);
            this.Sample_Copyright.Name = "Sample_Copyright";
            this.Sample_Copyright.Size = new System.Drawing.Size(286, 16);
            this.Sample_Copyright.TabIndex = 3;
            this.Sample_Copyright.Text = "Copyright";
            // 
            // Sample_Version
            // 
            this.Sample_Version.BackColor = System.Drawing.SystemColors.Control;
            this.Sample_Version.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.Sample_Version.Font = new System.Drawing.Font("Tahoma", 9.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.Sample_Version.Location = new System.Drawing.Point(159, 19);
            this.Sample_Version.Name = "Sample_Version";
            this.Sample_Version.Size = new System.Drawing.Size(286, 16);
            this.Sample_Version.TabIndex = 3;
            this.Sample_Version.Text = "Version: ";
            // 
            // AboutBox
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(525, 218);
            this.Controls.Add(this.Sample_Version);
            this.Controls.Add(this.Sample_Copyright);
            this.Controls.Add(this.Sample_Description);
            this.Controls.Add(this.buttonOK);
            this.Controls.Add(this.SRM_Logo);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "AboutBox";
            this.Padding = new System.Windows.Forms.Padding(9);
            this.ShowIcon = false;
            this.ShowInTaskbar = false;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.Text = "About this sample";
            ((System.ComponentModel.ISupportInitialize)(this.SRM_Logo)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.PictureBox SRM_Logo;
        private System.Windows.Forms.Button buttonOK;
        private System.Windows.Forms.TextBox Sample_Description;
        private System.Windows.Forms.TextBox Sample_Copyright;
        private System.Windows.Forms.TextBox Sample_Version;

    }
}
