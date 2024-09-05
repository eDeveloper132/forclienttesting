import mongoose, { Schema } from 'mongoose';
// Define the Message schema
const MessageSchema = new Schema({
    id: { type: String, required: true },
    u_id: { type: String, required: true }, // User ID to link messages to a user
    from: { type: String, required: false },
    to: { type: String, required: true },
    message: { type: String, required: true },
    m_count: { type: Number, required: true },
    cam_id: { type: String, required: false },
    m_schedule: { type: String, required: false },
    status: { type: String, required: true }
}, { timestamps: true });
// Define the Message model
const MessageModel = mongoose.model('MessageHandler', MessageSchema);
const SignSchema = new Schema({
    id: { type: String },
    Name: { type: String },
    Email: { type: String, required: true, unique: true },
    Password: { type: String },
    PhoneNumber: { type: String },
    Role: { type: String },
    Organization: { type: String },
    verificationToken: { type: String, default: null },
    verificationTokenExpiry: { type: Date, default: null },
    isVerified: { type: Boolean, default: false },
    Details: {
        PackageName: { type: String, default: null },
        PackageExpiry: { type: Date, default: null },
        Coins: { type: Number, default: null },
        Status: { type: String, default: null }
    },
    messages: [{ type: Schema.Types.ObjectId, ref: 'MessageModel' }],
    package: [{ type: Schema.Types.ObjectId, ref: 'PackageModel' }]
}, { timestamps: true });
// Define the Sign model
const SignModel = mongoose.model('SignHandler', SignSchema);
// Define the Token schema
const TokenSchema = new Schema({
    Token: { type: String, required: true, unique: true }
}, { timestamps: true });
// Define the Token model
const TokenModel = mongoose.model('TokenHandler', TokenSchema);
export { MessageModel, SignModel, TokenModel };
